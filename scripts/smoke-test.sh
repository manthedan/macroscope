#!/usr/bin/env bash
set -euo pipefail

scripts/validate-skill.py
.agents/skills/macroscope/scripts/macroscope-agent --help >/tmp/macroscope-skill-help.txt

cargo run -- --help >/tmp/macroscope-help.txt
cargo run -- --version >/tmp/macroscope-version.txt

rm -rf /tmp/macroscope-copied-skill
mkdir -p /tmp/macroscope-copied-skill/.agents/skills /tmp/macroscope-copied-skill/bin
cp -R .agents/skills/macroscope /tmp/macroscope-copied-skill/.agents/skills/macroscope
cp target/debug/macroscope /tmp/macroscope-copied-skill/bin/macroscope
printf '[package]\nname = "unrelated"\nversion = "0.1.0"\n' >/tmp/macroscope-copied-skill/Cargo.toml
/tmp/macroscope-copied-skill/.agents/skills/macroscope/scripts/macroscope-agent --version \
  | grep -q 'macroscope 0.3.0'

cargo run -- scan --json >/tmp/macroscope-scan.json
python3 -m json.tool /tmp/macroscope-scan.json >/dev/null
python3 - <<'PY'
import json
report = json.load(open('/tmp/macroscope-scan.json'))
assert report['schema_version'] == 4
assert 'nodes' in report['correlations']
PY

rm -rf /tmp/macroscope-state
XDG_STATE_HOME=/tmp/macroscope-state cargo run -- snapshot --name smoke-baseline >/tmp/macroscope-snapshot-output.txt
XDG_STATE_HOME=/tmp/macroscope-state cargo run -- history --json >/tmp/macroscope-history.json
python3 -c 'import json; h=json.load(open("/tmp/macroscope-history.json")); assert h[0]["name"] == "smoke-baseline"'
XDG_STATE_HOME=/tmp/macroscope-state cargo run -- diff --since smoke-baseline --json >/tmp/macroscope-managed-diff.json
python3 -m json.tool /tmp/macroscope-managed-diff.json >/dev/null

cargo run -- diff /tmp/macroscope-scan.json /tmp/macroscope-scan.json --json >/tmp/macroscope-diff.json
python3 -m json.tool /tmp/macroscope-diff.json >/dev/null

baseline_finding="$(python3 -c 'import json; r=json.load(open("/tmp/macroscope-scan.json")); items=r["findings"]+([x["finding"] for x in r["suppressed_findings"]]); print(items[0]["id"] if items else "")')"
if [[ -n "$baseline_finding" ]]; then
  cargo run -- verify /tmp/macroscope-scan.json --finding "$baseline_finding" --json >/tmp/macroscope-verify.json
else
  cargo run -- verify /tmp/macroscope-scan.json --json --strict >/tmp/macroscope-verify.json
fi
python3 -m json.tool /tmp/macroscope-verify.json >/dev/null

MACROSCOPE_DECISIONS=/tmp/macroscope-decisions.json cargo run -- decide smoke-test-finding snooze --days 1 --reason smoke
MACROSCOPE_DECISIONS=/tmp/macroscope-decisions.json cargo run -- decisions --json >/tmp/macroscope-decisions-output.json
MACROSCOPE_DECISIONS=/tmp/macroscope-decisions.json cargo run -- undecide smoke-test-finding

cargo run -- plan --json >/tmp/macroscope-plan.json
python3 -m json.tool /tmp/macroscope-plan.json >/dev/null
python3 -c 'import json; assert json.load(open("/tmp/macroscope-plan.json"))["schema_version"] == 3'
cargo run -- apply --dry-run /tmp/macroscope-plan.json >/tmp/macroscope-apply-preview.txt

cargo run -- brief --markdown /tmp/macroscope-brief.md --for-llm
cargo run -- guide --no-prompt --brief /tmp/macroscope-guide-brief.md

test -s /tmp/macroscope-brief.md
test -s /tmp/macroscope-guide-brief.md

echo "Smoke test passed"
