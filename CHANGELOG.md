# Changelog

All notable changes to Macroscope will be documented in this file.

## [0.1.0] - 2026-04-24

Initial public release.

### Added

- Read-only macOS developer-environment scan with pretty, JSON, and Markdown output.
- Homebrew inventory for prefix, formulae, casks, leaves, outdated packages, services, autoremove preview, and cleanup dry-run output.
- Application inventory for `/Applications` and `~/Applications`, including bundle IDs, versions, executable architecture, Intel-only app findings, and duplicate bundle ID findings.
- `/usr/local/bin` binary/symlink inventory with architecture detection and ownership heuristics.
- PATH ordering and duplicate entry checks.
- Developer-tool inventory for Node/npm globals, Cargo installs, Python/uv, Conda roots/envs/caches, and Go/GOPATH binaries.
- Read-only action planning with risk, confidence, destructive flags, and structured action kinds.
- `explain` command for paths, action IDs, bundle IDs, and finding text.
- `brief` command for compact human/AI handoff documents, including LLM guardrails and decision buckets.
- `guide` command for a guided scan → plan → decision → handoff/apply → verification workflow.
- Safe apply path that only executes Move-to-Trash actions and requires explicit `--yes`.
- Trash-backed cleanup that prefers direct `~/.Trash` moves for files/symlinks and Finder fallback where appropriate.

### Safety model

- `scan`, `plan`, `explain`, `brief`, and plain `guide` are read-only.
- `apply` refuses to mutate without `--yes`.
- `guide --no-prompt` never mutates.
- Package-manager and manual actions are printed for review and are not executed automatically.
- Only `MoveToTrash` actions execute automatically in v0.1.0.
