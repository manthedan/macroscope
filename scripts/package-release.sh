#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <rust-target> [output-directory]" >&2
  exit 64
fi

target="$1"
case "$target" in
  aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *)
    echo "unsupported release target: $target" >&2
    exit 64
    ;;
esac
out_dir="${2:-dist}"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd -P)"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
version="$(cd "$repo_root" && cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
name="macroscope-v${version}-${target}"
stage="$out_dir/$name"
archive="$out_dir/$name.tar.gz"

rm -rf "$stage" "$archive"
mkdir -p "$stage/bin" "$stage/.agents/skills"
cd "$repo_root"
cargo build --release --locked --target "$target"
cp "target/$target/release/macroscope" "$stage/bin/macroscope"
cp -R .agents/skills/macroscope "$stage/.agents/skills/macroscope"
cp README.md CHANGELOG.md LICENSE "$stage/"
chmod 755 "$stage/bin/macroscope" "$stage/.agents/skills/macroscope/scripts/macroscope-agent"
cat >"$stage/release.json" <<EOF
{
  "schema_version": 1,
  "version": "$version",
  "target": "$target",
  "binary": "bin/macroscope",
  "skill": ".agents/skills/macroscope/SKILL.md"
}
EOF

tar -C "$out_dir" -czf "$archive" "$name"
(
  cd "$out_dir"
  shasum -a 256 "$(basename "$archive")" >"$(basename "$archive").sha256"
)
echo "$archive"
