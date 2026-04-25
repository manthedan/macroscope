# Macroscope

Macroscope is a local-first macOS developer-environment auditor written in Rust.

It answers:

> What is installed on this Mac, where did it come from, is it native, and what is probably stale?

Macroscope deeply understands the Mac layer — Apple Silicon vs Intel leftovers, Homebrew prefixes, app bundles, `/usr/local/bin`, PATH, and ownership hints — while shallowly inventorying common developer ecosystems so ambiguous cleanup can be handed to a human or AI coding agent.

## Status

Macroscope is pre-1.0 software. It is intentionally conservative:

- read-only by default
- explain before action
- migration/reinstall guidance before deletion
- package-manager-owned files are review-only
- only Move-to-Trash actions execute automatically

## Installation

### From source

```bash
git clone https://github.com/manthedan/macroscope.git
cd macroscope
cargo install --path .
```

### Homebrew tap

After the tap is published:

```bash
brew tap manthedan/tap
brew install macroscope
```

## Quickstart

```bash
macroscope guide
macroscope brief --markdown macroscope-brief.md --for-llm
macroscope scan --markdown macroscope-report.md
macroscope plan --markdown macroscope-plan.md
```

For JSON output:

```bash
macroscope scan --json
macroscope plan --json
```

For a safe cleanup preview:

```bash
macroscope apply --dry-run
```

For real cleanup from an explicit reviewed plan:

```bash
macroscope plan --json > plan.json
macroscope apply --dry-run plan.json
macroscope apply --yes plan.json
```

## Commands

```bash
macroscope scan
macroscope scan --json
macroscope scan --markdown macroscope-report.md

macroscope plan
macroscope plan --json
macroscope plan --markdown macroscope-plan.md

macroscope brief
macroscope brief --markdown macroscope-brief.md --for-llm
macroscope brief --markdown macroscope-brief.md --for-llm --full

macroscope guide
macroscope guide --apply
macroscope guide --no-prompt

macroscope explain /usr/local/bin/aws
macroscope apply --dry-run
macroscope apply --yes plan.json
```

### `scan`

Collects local evidence and prints a pretty summary by default. JSON and Markdown output are available for automation or review.

### `plan`

Generates a read-only cleanup/migration action plan. Actions include risk, confidence, whether they are destructive, and a structured kind such as `MoveToTrash`, `BrewInstall`, or `Manual`.

### `brief`

Writes a compact human/AI handoff document. This is useful when you want to paste evidence into Codex, Claude Code, or another agent without asking Macroscope to encode every ecosystem-specific cleanup rule.

The brief separates:

- machine context
- high-confidence findings
- recommended decision buckets
- ecosystem notes needing judgment
- follow-up commands
- things not to automate
- questions to ask before cleanup
- raw evidence summary

Use `--full` to include uncapped finding/action detail.

### `guide`

A guided workflow:

```text
scan → plan → decision buckets → reports/brief/dry-run → optional guarded apply → optional verification
```

Plain `guide` is read-only. `guide --apply` enables guarded Move-to-Trash execution, still requiring dry-run and typed confirmation. `guide --no-prompt` never mutates.

### `explain`

Explains a path, action ID, bundle ID, or finding text and shows related planned actions.

### `apply`

Executes only supported action kinds. In v0.1.0 that means only `MoveToTrash` actions. Package-manager and manual actions are printed for review and are not executed automatically.

## What Macroscope scans

- System architecture and macOS version
- Homebrew prefix, formulae, casks, leaves, outdated packages, services, autoremove preview, and cleanup dry-run output
- `/Applications` and `~/Applications`
- Duplicate macOS app bundle identifiers
- App versions, bundle IDs, paths, and executable architecture
- Intel-only apps on Apple Silicon
- `/usr/local/bin` standalone binaries and symlinks, with ownership heuristics
- PATH ordering and duplicate entries
- Node/npm versions and global npm packages
- Cargo-installed crates
- Python/uv versions
- Conda install, platform, envs, env dirs, and package caches
- Go toolchain, GOPATH/GOBIN/GOROOT, and GOPATH/bin binary architectures

## Safety model

- `scan`, `plan`, `explain`, `brief`, and plain `guide` do not mutate the system.
- `guide --no-prompt` never mutates.
- Real CLI mutation requires `apply --yes`.
- Real guided mutation requires `guide --apply`, a dry-run, and typed confirmation.
- Only `MoveToTrash` actions execute automatically.
- File/symlink cleanup uses direct `~/.Trash` moves first, with Finder as fallback where appropriate.
- Package-manager actions are review-only for now.
- High-risk actions such as app support deletion, shell init edits, Conda root removal, LaunchAgent removal, and broad package-manager cleanup are manual/handoff items.

## Scope

Macroscope should deeply understand the Mac developer-environment layer and shallowly inventory language/tool ecosystems.

In scope:

- Apple Silicon migration leftovers
- Homebrew prefix/ownership issues
- duplicate app bundles
- stale local binaries
- PATH problems
- common developer-tool inventories
- explainable action plans
- human/AI handoff briefs
- safe reversible cleanup

Out of scope by default:

- full package-manager abstraction
- automatic Conda/npm/Java/Go ecosystem management
- broad system cleaner behavior
- risky deletion without explicit confirmation

## Project layout

```text
src/main.rs      CLI argument parsing and command dispatch
src/lib.rs       library module wiring and focused unit tests
src/model.rs     shared report/action data structures
src/scan.rs      scan orchestration and source-specific scanners
src/findings.rs  finding generation and reusable finding helpers
src/plan.rs      ActionPlan generation, rendering, and relation matching
src/brief.rs     human/AI handoff brief rendering
src/guide.rs     guided scan/plan/handoff/apply workflow
src/apply.rs     dry-run/apply execution and Trash-backed moves
src/markdown.rs  Markdown report rendering
src/output.rs    pretty terminal output and explanations
src/util.rs      command/path/formatting helpers
```

## Development

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
scripts/smoke-test.sh
```

## License

MIT
