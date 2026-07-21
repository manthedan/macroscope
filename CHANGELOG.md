# Changelog

All notable changes to Macroscope will be documented in this file.

## [0.3.0] - 2026-07-15

### Added

- Listener exposure classification for loopback, LAN, Tailscale, wildcard, public, and unknown bindings.
- Focused `explain --port`, `explain --pid`, and `graph --finding` investigation workflows.
- Managed named snapshots, `history`, and `diff --since` under the user state directory.
- Exact approval-gated launchctl and process remediation argv with structured preconditions, undo, and verification.
- Process-group and parent-command evidence for zombie findings.

### Changed

- Report schema is now version 4 and action-plan schema is version 3.
- Intel-only app findings are informational and collapsed in default terminal output while remaining available in JSON and Markdown.

## [0.2.0] - 2026-07-14

### Added

- Agent Skills-compatible workflow at `.agents/skills/macroscope/SKILL.md` with a source-aware CLI wrapper.
- Third-party LaunchAgent and LaunchDaemon inventory with KeepAlive, RunAtLoad, program, scope, associated bundle IDs, and parent-app correlation.
- Runtime process and TCP-listener inventory.
- Versioned/timestamped evidence reports with stable finding IDs, categories, confidence, and structured evidence.
- Runtime command-line redaction for common token, password, secret, credential, and API-key arguments.
- Fixture-backed detections for suspicious KeepAlive jobs, AppTranslocation persistence, orphaned privileged helpers, old detached wildcard listeners, detached agent-browser groups, and zombie processes.
- Persistence/runtime findings now produce cautious manual remediation plans.
- Versioned `snapshot`, stable-ID `diff`, and targeted `verify` workflows.
- Correlation graph linking launch items, processes, listeners, executables, applications, and inferred packages.
- Persistent keep/ignore/snooze decisions keyed by stable finding ID.
- Versioned action controls for provenance, preconditions, administrator requirements, undo, and verification.
- Release packaging that ships the native binary and matching Agent Skill in one checksummed archive.

### Changed

- Repositioned Macroscope as an agent-first macOS evidence and remediation engine while retaining the human guide as a fallback.
- JSON, Markdown, terminal, and handoff output now include persistence/runtime evidence.
- Automatic cleanup now rejects protected/arbitrary paths, stale externally supplied actions, duplicate IDs, and plans without matching safeguards.

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
