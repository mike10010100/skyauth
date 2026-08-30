#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, missing_docs)]

use skyauth::error::SsrfError;
use skyauth::ssrf::SsrfFilter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn raw_server(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await;
        if socket.write_all(&response).await.is_ok() {
            let _ = socket.flush().await;
            let _ = socket.shutdown().await;
        }
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn cross_origin_redirect_is_rejected() {
    let destination = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("unexpected"))
        .mount(&destination)
        .await;
    let source = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/target", destination.uri())),
        )
        .mount(&source)
        .await;

    let result = SsrfFilter::new(true)
        .safe_get(&format!("{}/start", source.uri()), 1024)
        .await;
    assert!(matches!(result, Err(SsrfError::CrossOriginRedirect)));
}

#[tokio::test]
async fn chunked_body_stops_at_the_limit() {
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    response.extend_from_slice(b"1770\r\n");
    response.extend(std::iter::repeat_n(b'a', 6000));
    response.extend_from_slice(b"\r\n1770\r\n");
    response.extend(std::iter::repeat_n(b'b', 6000));
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    let (origin, server) = raw_server(response).await;

    let result = SsrfFilter::new(true).safe_get(&origin, 10_000).await;
    assert!(matches!(result, Err(SsrfError::ResponseTooLarge { .. })));
    server.await.unwrap();
}

#[tokio::test]
async fn encoded_body_is_rejected_before_reading() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\ntest".to_vec();
    let (origin, server) = raw_server(response).await;

    let result = SsrfFilter::new(true).safe_get(&origin, 1024).await;
    assert!(matches!(result, Err(SsrfError::UnsupportedContentEncoding)));
    server.await.unwrap();
}

#[tokio::test]
async fn any_non_identity_content_encoding_is_rejected() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\ntest".to_vec();
    let (origin, server) = raw_server(response).await;

    let result = SsrfFilter::new(true).safe_get(&origin, 1024).await;
    assert!(matches!(result, Err(SsrfError::UnsupportedContentEncoding)));
    server.await.unwrap();
}

#[tokio::test]
async fn excessive_response_headers_are_bounded() {
    let mut response = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
    response.extend(std::iter::repeat_n(b'a', 70_000));
    response.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
    let (origin, server) = raw_server(response).await;

    let result = SsrfFilter::new(true).safe_get(&origin, 1024).await;
    assert!(matches!(
        result,
        Err(SsrfError::HeadersTooLarge { .. }) | Err(SsrfError::Http(_))
    ));
    server.await.unwrap();
}

fn contains_constructor(source: &str, pattern: &str) -> bool {
    source.match_indices(pattern).any(|(index, _)| {
        index == 0
            || source
                .as_bytes()
                .get(index.saturating_sub(1))
                .is_some_and(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
    })
}

#[test]
fn production_sources_use_only_the_central_client_builder() {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![source_root];
    let mut constructors = Vec::new();
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).unwrap();
                let is_transport = path.ends_with("src/ssrf.rs");
                if is_transport {
                    if source.matches("reqwest::Client::builder()").count() != 1 {
                        constructors.push(format!(
                            "{}: expected exactly one centralized client builder",
                            path.display()
                        ));
                    }
                    continue;
                }
                for pattern in [
                    "reqwest::Client::builder()",
                    "reqwest::Client::new()",
                    "reqwest::ClientBuilder::new()",
                    "Client::builder()",
                    "Client::new()",
                    "ClientBuilder::new()",
                ] {
                    if contains_constructor(&source, pattern) {
                        constructors.push(format!("{}: {pattern}", path.display()));
                    }
                }
                if source
                    .lines()
                    .any(|line| line.contains("use reqwest") && line.contains("Client"))
                {
                    constructors.push(format!(
                        "{}: imported reqwest client constructor",
                        path.display()
                    ));
                }
            }
        }
    }
    assert!(
        constructors.is_empty(),
        "production reqwest clients bypass SafeHttpClient: {constructors:?}"
    );
}
