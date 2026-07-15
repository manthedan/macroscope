---
name: macroscope
description: Audits macOS persistence, processes, listening ports, privileged-helper remnants, applications, Homebrew, PATH, and developer-tool leftovers. Use when investigating unexpected background services, orphaned processes, stale development environments, old-Mac cleanup, Intel leftovers on Apple Silicon, or when a user wants a cautious cleanup plan with before/after verification.
license: MIT
compatibility: macOS; requires the macroscope binary or Rust/Cargo to run the bundled source checkout.
---

# Macroscope

Use Macroscope as the deterministic evidence layer. You provide contextual judgment; Macroscope inventories, correlates, plans, and verifies.

## Resolve the CLI

Resolve commands relative to this `SKILL.md`. From the Macroscope repository root, the bundled wrapper is:

```bash
.agents/skills/macroscope/scripts/macroscope-agent --version
```

In a checkout it runs the matching Cargo source; in a release archive it uses the bundled binary, then falls back to `macroscope` on `PATH`. Set `MACROSCOPE` to the wrapper's absolute path (or simply `macroscope` when installed):

```bash
MACROSCOPE="$(pwd)/.agents/skills/macroscope/scripts/macroscope-agent"
```

## Workflow

### 1. Capture evidence before changing anything

```bash
"$MACROSCOPE" snapshot --name before-cleanup
"$MACROSCOPE" graph --json > /tmp/macroscope-graph.json
"$MACROSCOPE" brief --markdown /tmp/macroscope-brief.md --for-llm --full
"$MACROSCOPE" plan --json > /tmp/macroscope-plan.json
```

Read the brief and query the JSON artifacts selectively. Prioritize `persistence` and `runtime` findings. Follow graph edges from launch item → process → listener/executable → application or package before recommending action.

### 2. Inspect high-value findings

Pay particular attention to:

- third-party launch items with `KeepAlive`
- launch items pointing into AppTranslocation or temporary paths
- privileged helpers with no matching parent app
- old PPID-1 processes listening on wildcard interfaces
- detached agent-browser/Chrome groups
- zombie processes and their parents

Use `macroscope explain <finding-id>`, `macroscope explain --port <port>`, `macroscope explain --pid <pid>`, and `macroscope graph --finding <finding-id>` for focused investigation. When the user confirms intentional state, record it rather than repeatedly warning:

```bash
"$MACROSCOPE" decide '<finding-id>' keep --reason 'user confirmed intentional'
"$MACROSCOPE" decide '<finding-id>' snooze --days 14 --reason 'review later'
```

Use `ignore` only when the user wants the signal permanently excluded without asserting that the underlying software should be kept.

### 3. Ask before mutation

Treat findings as evidence, not permission. Before killing, unloading, uninstalling, or deleting:

- ask whether the related app/tool/project is still used
- verify process command, cwd, age, listeners, and ownership
- prefer vendor uninstallers or package-manager commands
- stop/unload a service before deleting persistence
- call out actions requiring administrator authentication

Never run `apply --yes` against an unreviewed plan. Inspect each action's provenance, preconditions, `requires_root`, undo steps, exact command argv, and verification checks. Macroscope revalidates executable actions against a fresh scan, but that does not replace consent.

### 4. Execute the smallest approved action

Macroscope currently executes only reviewed Move-to-Trash actions. Persistence removal, privileged helpers, package-manager work, and process termination remain agent/human actions.

Always preview Macroscope-managed actions:

```bash
"$MACROSCOPE" apply --dry-run /tmp/macroscope-plan.json
```

For root-owned cleanup, present exact commands or a reviewable script and stop for administrator authentication. Do not solicit, store, or echo passwords.

### 5. Verify

After approved cleanup:

```bash
"$MACROSCOPE" diff --since before-cleanup
"$MACROSCOPE" verify ~/.local/state/macroscope/snapshots/before-cleanup.json --finding '<finding-id>' --strict
"$MACROSCOPE" snapshot /tmp/macroscope-after.json
```

Verify all relevant invariants directly:

- launchd label is absent or disabled
- process is gone
- listener port is closed, with its loopback/LAN/Tailscale/wildcard/public exposure understood
- plist/helper/package path is gone when removal was approved
- unrelated active services remain running

Summarize what changed, what remains, and what was blocked by required authentication.

## Safety boundaries

- Do not equate PPID 1 with orphaned; many legitimate processes are launchd-managed.
- Do not kill all processes matching a broad substring when exact PID/command checks are possible.
- Do not remove root helpers merely because they are idle; first establish that the parent product is absent or unused.
- Do not infer staleness from Intel architecture alone. Add ownership, version, size, usage, and replacement evidence.
- Preserve user data unless the user explicitly requests its deletion.
