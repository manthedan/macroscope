# Macroscope

Macroscope is a local-first macOS developer environment auditor written in Rust.

The goal is to answer: **what is installed on this Mac, where did it come from, is it native, and what is probably stale?**

## Current MVP

```bash
cargo run -- scan
cargo run -- scan --markdown macroscope-report.md
cargo run -- scan --json
cargo run -- plan
cargo run -- plan --markdown cleanup-plan.md
cargo run -- brief --markdown macroscope-brief.md --for-llm
cargo run -- guide
cargo run -- guide --apply
cargo run -- explain /usr/local/bin/aws
cargo run -- apply --dry-run
cargo run -- apply --yes plan.json
cargo run -- tui
cargo run -- tui --apply
```

`scan` prints a pretty table-based summary by default. `plan` generates a read-only cleanup/migration action plan. `brief` writes a human/AI handoff document that separates high-confidence evidence from ambiguous review items. `guide` walks through scan → plan → decision → safe apply/manual/handoff → optional verification. `explain` gives detail for a path, action ID, bundle ID, or finding text. `apply --dry-run` previews what an action plan would do without changing anything. `apply --yes` can execute safe move-to-Trash actions while printing package-manager/manual actions for review. File/symlink cleanup uses a direct `~/.Trash` move first to avoid Finder Automation permission prompts, with Finder as a fallback. `tui` opens an optional interactive terminal dashboard with Findings and Plan tabs. Plain `tui` is read-only; `tui --apply` enables guarded Move-to-Trash execution after dry-run and typed confirmation.

TUI controls:

```text
Tab / f / p  switch Findings/Plan
j/k or ↑/↓   move selection
e            explain selected finding/action
d / D        dry-run selected action, or related finding actions / whole plan
x / m        export plan JSON / Markdown
r            rescan and regenerate plan
a / A        apply selected / all executable actions in --apply mode only
?            help
q / Esc      close modal or quit
```

The initial scanner audits:

- System architecture and macOS version
- Homebrew formulae, casks, leaves, outdated packages, services, and cleanup dry-run output
- `/Applications` and `~/Applications`
- Duplicate macOS app bundle identifiers
- App versions, bundle IDs, paths, and executable architecture
- Intel-only apps on Apple Silicon
- `/usr/local/bin` standalone binaries and symlinks, with ownership heuristics
- `PATH` ordering and duplicate entries
- Node/npm versions and global npm packages
- Cargo-installed crates
- Python/uv versions
- Conda install, platform, envs, env dirs, and package caches
- Go toolchain, GOPATH/GOBIN/GOROOT, and GOPATH/bin binary architectures
- Pretty terminal output with scan progress animation
- Interactive TUI dashboard with scan/rescan progress animation
- Read-only ActionPlan generation
- `explain` for paths/action IDs/bundle IDs/finding text
- Dry-run ActionPlan executor
- TUI ActionPlan context and related actions
- TUI Plan tab with action detail browsing
- TUI dry-run, export, explain, rescan, and guarded apply controls

## Project layout

Macroscope is split into focused Rust modules:

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
src/tui.rs       optional ratatui dashboard, progress UI, and guarded TUI apply flow
src/markdown.rs  Markdown report rendering
src/output.rs    pretty terminal output and explanations
src/util.rs      command/path/formatting helpers
```

## Why npm belongs here

Yes: if this is dev-focused, npm/global Node tooling should absolutely be part of the audit.

Global npm packages are one of the most common sources of stale developer tools because they can overlap with:

- Homebrew formulae
- standalone app bundles
- `npx`/project-local tools
- old Node versions managed by nvm
- manual scripts in `/usr/local/bin`

Eventually Macroscope should also audit:

- npm global packages per nvm Node version
- pnpm global packages
- yarn global packages
- Python tools installed through `pipx`, `uv`, and user-site packages
- Ruby gems
- Go binaries in `~/go/bin`
- VS Code/Cursor extensions
- Launch agents/daemons
- login items
- shell startup files that mutate `PATH`

## Design principles

- Read-only by default
- Explain before suggesting deletion
- Prefer native Apple Silicon tooling on Apple Silicon
- Detect duplicate installs across package managers
- Generate Markdown reports that are easy to review
- Interactive cleanup should always have a dry-run mode

## Roadmap

Near-term priorities are tracked in detail in [`ROADMAP.md`](ROADMAP.md). The next likely work is:

1. Improve `brief` into the best possible handoff artifact for humans, Codex, Claude Code, or another agent.
2. Improve `guide` into the primary interactive workflow: scan, plan, choose apply/manual/handoff/ignore, then verify.
3. Improve finding structure and evidence quality so all outputs become more trustworthy.
4. Add ecosystem intelligence only where it makes findings more actionable; hand off ambiguous cleanup instead of over-automating.
5. Add cautious package-manager execution paths only after better dry-run/confirmation and ownership metadata.
6. Deepen app cleanup intelligence while keeping deletion Trash-backed and explicitly confirmed.

### Phase 1: Better reports

- Add tables for apps and binaries
- Classify findings by confidence and category
- Include modified dates and app versions
- Detect quarantine attributes

### Phase 2: Package-manager coverage

- Homebrew services and outdated packages
- npm/pnpm/yarn globals
- Cargo installs and stale crates
- Python `uv tool`, `pipx`, and user-site packages
- richer Go module provenance for `~/go/bin` binaries

### Phase 3: Explain and plan

```bash
macroscope explain /Applications/VirtualBox.app
macroscope explain trash-usr-local-bin-aws
macroscope plan --markdown cleanup-plan.md
macroscope apply --dry-run
```

### Phase 4: TUI

A `ratatui` interface for browsing findings and approving cleanup actions.
