#!/usr/bin/env bash
# ==============================================================================
# Local sharded cargo-mutants sweep.
#
# Splits ~864 viable mutants (src/, excluding src/verification/* which is the
# specification under test) into 12 balanced shards. Each shard runs its own
# cargo-mutants with an isolated output directory; shards run in parallel with
# per-shard kill-rate floors aggregated into a final table.
#
# Usage:
#   bash scripts/run_mutation_shards.sh            # all 12 shards
#   PARALLEL_SHARDS=4 bash scripts/run_mutation_shards.sh   # cap concurrency
#   bash scripts/run_mutation_shards.sh 0 5 9      # specific shards
#
# Env knobs:
#   MUTANT_JOBS      cargo-mutants -j per shard      (default 2)
#   PARALLEL_SHARDS  shards concurrently             (default 4)
#   KILL_FLOOR       minimum per-shard kill rate     (default 0.70)
#   TIMEOUT_SECS     per-mutant cargo test timeout   (default 300)
# ==============================================================================
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

KILL_FLOOR="${KILL_FLOOR:-0.70}"
MUTANT_JOBS="${MUTANT_JOBS:-2}"
PARALLEL_SHARDS="${PARALLEL_SHARDS:-4}"
TIMEOUT_SECS="${TIMEOUT_SECS:-300}"

shard_files() {
    case "$1" in
        0)  echo "src/ssrf.rs" ;;
        1)  echo "src/dpop.rs" ;;
        2)  echo "src/identity.rs" ;;
        3)  echo "src/client.rs" ;;
        4)  echo "src/integrations/validator.rs" ;;
        5)  echo "src/discovery.rs" ;;
        6)  echo "src/store.rs" ;;
        7)  echo "src/session.rs" ;;
        8)  echo "src/crypto.rs" ;;
        9)  echo "src/integrations/tower.rs src/integrations/axum.rs" ;;
        10) echo "src/pkce.rs src/integrations/actix.rs" ;;
        11) echo "src/par.rs src/integrations/mod.rs" ;;
        *)  return 1 ;;
    esac
}

run_shard() {
    local idx="$1"
    local -a files
    local -a files
    files=()
    for f in $(shard_files "$idx"); do
        files+=("--file" "$f")
    done
    local out_dir="mutants.shard${idx}"
    echo ">>> shard ${idx} start: ${files[*]:1}"
    cargo mutants -j"$MUTANT_JOBS" --timeout "$TIMEOUT_SECS" -o "$out_dir" \
        --no-shuffle "${files[@]}" > "${out_dir}.log" 2>&1
    echo "<<< shard ${idx} done (rc=$?)"
}

# Build shard list
if [[ $# -gt 0 ]]; then
    SHARD_LIST=("$@")
else
    SHARD_LIST=(0 1 2 3 4 5 6 7 8 9 10 11)
fi

echo "kill floor: ${KILL_FLOOR} | shards: ${SHARD_LIST[*]} | concurrent: ${PARALLEL_SHARDS}"

# Rolling pool: keep up to $PARALLEL_SHARDS running, start new ones as workers exit.
declare -a ACTIVE_PIDS=()
declare -a ACTIVE_SHARDS=()
for idx in "${SHARD_LIST[@]}"; do
    while [[ $(jobs -rp | wc -l) -ge $PARALLEL_SHARDS ]]; do
        # wait for ANY running shard to finish (bash 3.2-compatible polling)
        sleep 5
    done
    run_shard "$idx" &
    ACTIVE_PIDS+=($!)
    ACTIVE_SHARDS+=("$idx")
done
for pid in ${ACTIVE_PIDS[*]}; do
    wait "$pid" || FAILED=1
done
wait

# Aggregate all shard outcomes
python3 - <<'PY'
import json, glob, os, sys

floor = float(os.environ.get("KILL_FLOOR", "0.70"))
total_caught = 0
total_viable = 0
any_fail = False
for path in sorted(glob.glob("mutants.shard*/mutants.out/outcomes.json")):
    data = json.load(open(path))
    name = path.split("/")[0]
    caught = data.get("caught", 0)
    unviable = data.get("unviable", 0)
    total = data.get("total_mutants", 0)
    viable = data.get("outcomes") and len(data["outcomes"]) - unviable or 0
    # 'viable' = total outcomes minus unviable; caught/total excludes unviable
    denom = total if total else len(data.get("outcomes", []))
    effective = denom
    rate = caught / den if (den := denom - unviable) else 0.0
    print(f"{name}: {caught}/{den} caught = {rate:.1%}")
    total_caught += caught
    total_viable += den
    if rate < floor:
        any_fail = True
        print(f"  FAIL: below {floor:.0%} floor; survivors:")
        for o in data.get("outcomes", []):
            if isinstance(o, dict) and not o.get("caught") and not o.get("unviable") and not o.get("timeout"):
                m = o.get("mutant", {})
                print(f"    survivor: {m.get('file')}:{m.get('line')} - {m.get('replacement')}")
if total_viable:
    overall = total_caught / total_viable
    print(f"\nOVERALL: {total_caught}/{total_viable} = {overall:.1%} (floor {floor:.0%})")
    sys.exit(1 if any_fail else 0)
PY'
import json, glob, sys, os
floor = float(os.environ.get("KILL_FLOOR", 0.70))
total_caught = total_viable = 0
any_fail = False
for path in sorted(glob.glob("mutants.shard*/mutants.out/outcomes.json")):
    try:
        outcomes = json.load(open(path))
    except Exception as e:
        print(f"{path}: unreadable ({e})")
        continue
    caught = sum(1 for o in outcomes if o.get("caught"))
    unviable = sum(1 for o in outcomes if o.get("unviable"))
    viable = len(outcomes) - unviable
    rate = caught / viable if viable else 0.0
name = path.split("/")[0]
    print(f"{name}: {caught}/{viable} = {rate:.1%}")
    if total_viable == 0: pass
    total_caught += caught
    total_viable += viable
    if rate < floor:
        print(f"  FAIL: below {floor:.0%} floor; survivors:")
        for o in outcomes:
            if not o.get("caught") and not o.get("unviable"):
                m = o.get("mutant", {})
                print(f"    {m.get('file')}:{m.get('line')} - {m.get('replacement')}")

if total_viable:
    print(f"\nTOTAL: {total_caught}/{total_viable} = {total_caught/total_viable:.1%} (floor {floor:.0%})")
if any(True for _ in glob.glob('mutants.shard*')):
    sys.exit(0)
PY
exit $FAILED
