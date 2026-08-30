//! Resolves an AT Protocol identity and discovers its authorization server.

use skyauth::identity::IdentityResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identifier = std::env::args().nth(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: live_discovery <handle-or-did>",
        )
    })?;
    let _endpoints = IdentityResolver::builder()
        .build()
        .discover_oauth_endpoints(&identifier)
        .await?;

    println!("discovery succeeded");
    Ok(())
}
