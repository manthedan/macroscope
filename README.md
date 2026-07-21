<p align="center">
  <img src="assets/macroscope-lockup.svg" alt="Macroscope — developer environment archaeology for your Mac" width="860">
</p>

# Macroscope

Macroscope is a local-first macOS evidence and remediation engine written in Rust. It is designed to be run by an AI agent or a human who wants deterministic evidence before cleanup.

It answers:

> What persists, what is running or listening, where did it come from, and what is probably stale or broken?

Macroscope correlates third-party launch items, processes, TCP listeners, privileged helpers, applications, package-manager ownership, Apple Silicon leftovers, `/usr/local/bin`, PATH, and developer ecosystems. It emits structured JSON and cautious plans so an agent can apply contextual judgment without rediscovering the machine from scratch.

## Status

Macroscope is pre-1.0 software. It is intentionally conservative:

- read-only by default
- explain before action
- migration/reinstall guidance before deletion
- package-manager-owned files are review-only
- common command-line secret arguments are redacted from runtime evidence
- only Move-to-Trash actions execute automatically

## Installation

### From source

```bash
git clone https://github.com/manthedan/macroscope.git
cd macroscope
cargo install --path .
```

### Binary + Agent Skill release archive

Each GitHub release publishes checksummed Apple Silicon and Intel archives containing both `bin/macroscope` and the matching `.agents/skills/macroscope` package. Put the binary on `PATH` and copy or symlink the skill into `~/.agents/skills/macroscope`.

Maintainers produce the same archive locally with:

```bash
scripts/package-release.sh aarch64-apple-darwin
```

### Homebrew tap

```bash
brew tap manthedan/tap
brew install macroscope
```

## Quickstart

For an agent-oriented evidence pass:

```bash
macroscope snapshot --name before-cleanup
macroscope graph --json > /tmp/macroscope-graph.json
macroscope brief --markdown /tmp/macroscope-brief.md --for-llm --full
macroscope plan --json > /tmp/macroscope-plan.json
```

After approved cleanup, compare and verify stable findings:

```bash
macroscope diff --since before-cleanup
macroscope verify ~/.local/state/macroscope/snapshots/before-cleanup.json --finding '<finding-id>' --strict
```

For a human-readable workflow:

```bash
macroscope scan --markdown macroscope-report.md
macroscope plan --markdown macroscope-plan.md
macroscope guide
```

### Agent Skill

The repository includes an Agent Skills-compatible package at:

```text
.agents/skills/macroscope/SKILL.md
```

Pi and other compatible harnesses discover it when the repository is trusted and in scope. To install it globally, copy or symlink `.agents/skills/macroscope` into `~/.agents/skills/macroscope`. In a source checkout, the skill wrapper runs the matching Cargo project; release archives bundle a native binary and the matching skill together.

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
macroscope snapshot before.json
macroscope snapshot --name post-cleanup
macroscope history
macroscope diff before.json [after.json]
macroscope diff --since post-cleanup
macroscope verify before.json --finding '<finding-id>' --strict
macroscope graph --json
macroscope graph --finding '<finding-id>'

macroscope decide '<finding-id>' keep --reason 'intentional service'
macroscope decide '<finding-id>' snooze --days 14
macroscope decisions --json
macroscope undecide '<finding-id>'

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
macroscope explain --port 8765
macroscope explain --pid 994
macroscope apply --dry-run
macroscope apply --yes plan.json
```

### `scan`

Collects local evidence and prints a pretty summary by default. JSON and Markdown output are available for automation or review.

### `snapshot`, `diff`, and `verify`

`snapshot` stores a versioned evidence report. Use `--name` (or omit the output path) for managed storage under `~/.local/state/macroscope/snapshots`; `history` lists those baselines. `diff --since <name>` compares a managed baseline with a fresh scan. `diff` compares stable finding IDs, launch-item definitions, listeners, and graph size. `verify` checks selected findings—or all baseline persistence/runtime warnings by default—against current state. Use `--strict` when an agent or CI workflow needs a failing exit status for unresolved targets.

### `graph`

Emits the correlation graph connecting launch labels, processes, listeners, executable paths, applications, and inferred package ownership. `--finding <id>` returns only the connected evidence neighborhood for focused investigation.

### `decide`, `decisions`, and `undecide`

Records durable `keep`, `ignore`, or time-limited `snooze` decisions in `~/.config/macroscope/decisions.json`. Decisions suppress matching stable finding IDs without deleting the underlying evidence from snapshots.

### `plan`

Generates a read-only cleanup/migration action plan. Actions include risk, confidence, provenance, preconditions, root requirements, exact reviewed argv for process/launchd remediation, undo steps, verification checks, and a structured kind such as `MoveToTrash`, `BrewInstall`, or `Manual`. Exact launchctl/kill steps remain approval-gated and are never executed as automatic actions.

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

Explains a path, action ID, bundle ID, finding text, TCP port (`--port`), or process (`--pid`) and shows parent, listener, launchd, finding, and planned-action evidence.

### `apply`

Executes only supported action kinds. Only guarded `MoveToTrash` actions under `/usr/local/bin` execute automatically. Package-manager, process, launchd, and other manual actions are printed for review and are not executed automatically. Real apply rejects stale externally supplied actions, duplicate IDs, protected/arbitrary paths, and missing safeguards.

## What Macroscope scans

- Third-party LaunchAgents and LaunchDaemons, including KeepAlive, RunAtLoad, executable paths, and associated apps
- Correlation chains from launch labels through processes/listeners to executables and app/package provenance
- Processes, PPIDs, process groups, age, state, CPU/memory, and commands
- TCP listeners classified as loopback, LAN, Tailscale, wildcard, public, or unknown, with process ownership
- Broken AppTranslocation persistence, orphaned privileged helpers, old detached listeners, detached agent browsers, and zombies
- System architecture and macOS version
- Homebrew prefix, formulae, casks, leaves, outdated packages, services, autoremove preview, and cleanup dry-run output
- `/Applications` and `~/Applications`
- Duplicate macOS app bundle identifiers
- App versions, bundle IDs, paths, and executable architecture
- Intel-only apps on Apple Silicon, collapsed in default terminal output while retained in JSON/Markdown
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
- Only freshly revalidated `MoveToTrash` actions for direct `/usr/local/bin` children execute automatically.
- File/symlink cleanup uses direct `~/.Trash` moves first, with Finder as fallback where appropriate.
- Package-manager actions are review-only for now.
- High-risk actions such as app support deletion, shell init edits, Conda root removal, LaunchAgent removal, and broad package-manager cleanup are manual/handoff items.

## Scope

Macroscope should deeply understand macOS persistence/runtime hygiene and the Mac developer-environment layer, while shallowly inventorying language/tool ecosystems. The CLI is the deterministic evidence and guarded-execution layer; human or AI agents own contextual judgment.

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
src/snapshot.rs  versioned snapshot, stable diff, and verification workflows
src/correlation.rs evidence graph construction and rendering
src/decisions.rs persistent keep/ignore/snooze decisions
src/lib.rs       library module wiring and focused unit tests
src/model.rs     shared report/action data structures
src/scan.rs      scan orchestration and source-specific scanners
src/findings.rs  finding generation and reusable finding helpers
src/plan.rs      ActionPlan generation, rendering, and relation matching
src/brief.rs     human/AI handoff brief rendering
src/guide.rs     guided scan/plan/handoff/apply workflow
src/hygiene.rs   persistence/runtime collectors, parsers, correlation, and anomaly detection
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
