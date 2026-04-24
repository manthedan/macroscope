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
cargo run -- explain /usr/local/bin/aws
cargo run -- apply --dry-run
cargo run -- apply --yes plan.json
cargo run -- tui
```

`scan` prints a pretty table-based summary by default. `plan` generates a read-only cleanup/migration action plan. `explain` gives detail for a path, action ID, bundle ID, or finding text. `apply --dry-run` previews what an action plan would do without changing anything. `apply --yes` can execute safe move-to-Trash actions while printing package-manager/manual actions for review. `tui` opens an interactive terminal dashboard with Findings and Plan tabs. Press `Tab` to switch tabs, `↑/↓` or `j/k` to move, `f`/`p` to jump to Findings/Plan, and `q` or `Esc` to exit.

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
- Pretty terminal output
- Interactive TUI dashboard
- Read-only ActionPlan generation
- `explain` for paths/action IDs/bundle IDs/finding text
- Dry-run ActionPlan executor
- TUI ActionPlan context and related actions
- TUI Plan tab with action detail browsing

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
