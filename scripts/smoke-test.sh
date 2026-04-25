#!/usr/bin/env bash
set -euo pipefail

cargo run -- --help >/tmp/macroscope-help.txt
cargo run -- --version >/tmp/macroscope-version.txt

cargo run -- scan --json >/tmp/macroscope-scan.json
python3 -m json.tool /tmp/macroscope-scan.json >/dev/null

cargo run -- plan --json >/tmp/macroscope-plan.json
python3 -m json.tool /tmp/macroscope-plan.json >/dev/null

cargo run -- brief --markdown /tmp/macroscope-brief.md --for-llm
cargo run -- guide --no-prompt --brief /tmp/macroscope-guide-brief.md

test -s /tmp/macroscope-brief.md
test -s /tmp/macroscope-guide-brief.md

echo "Smoke test passed"
