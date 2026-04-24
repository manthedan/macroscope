# Macroscope Roadmap

Macroscope should become a trustworthy developer-environment archaeologist: it audits a Mac, explains what it found, and produces safe, reversible cleanup or migration plans.

## Product principles

1. **Read-only by default**
   - `scan`, `explain`, and `plan` should not modify the system.
   - Any mutation belongs behind explicit `apply`/interactive confirmation.

2. **Explain before action**
   - Every suggested action needs a rationale.
   - Destructive actions need risk and confidence labels.

3. **Prefer ownership-aware cleanup**
   - Use `brew uninstall`, `cargo uninstall`, `npm uninstall -g`, etc. when ownership is known.
   - Avoid deleting package-manager-owned files directly.

4. **Prefer reversible operations**
   - Move files/apps to Trash instead of permanent deletion where possible.
   - Dry-run should always be available before apply.
   - Real apply requires explicit `--yes`.

5. **Migration beats deletion when possible**
   - For stale Intel tools, suggest native ARM replacements first.
   - Verify replacement before removing the old copy.

## Command roadmap

### `macroscope scan`

Current: pretty read-only audit.

Planned:

- Better categories and finding IDs
- More precise app architecture detection
- Modified/opened dates where available
- Quarantine and code-signing status
- Package-manager ownership detection

### `macroscope tui`

Current: interactive dashboard with selectable Findings and Plan tabs, plan summary, related actions, and action detail browsing.

Planned:

- More tabs: Apps, Binaries, Packages
- Search/filter by severity/category/path
- Per-finding explanation pane
- Suggested actions pane
- Select actions for a future dry-run/apply flow

### `macroscope plan`

Current: generate a read-only action plan from scan findings.

Planned:

```bash
macroscope plan
macroscope plan --json
macroscope plan --markdown cleanup-plan.md
```

The plan should contain:

- Action ID
- Title
- Rationale
- Confidence
- Risk
- Whether the action is destructive
- Structured action kind, e.g. `MoveToTrash`, `BrewInstall`, `Manual`

### `macroscope explain`

Current: explain paths, action IDs, bundle IDs, or text found in findings.

```bash
macroscope explain /usr/local/bin/aws
macroscope explain trash-usr-local-bin-aws
macroscope explain com.adobe.Photoshop
```

Should answer:

- What is this?
- Why was it flagged?
- Who probably owns it?
- Is there a safer native replacement?
- What actions are available?

### `macroscope apply`

Current: dry-run generated plans or JSON plan files, and execute move-to-Trash actions only with explicit confirmation.

```bash
macroscope apply --dry-run
macroscope apply plan.json --dry-run
macroscope apply --yes plan.json
```

Package-manager and manual actions are printed for review rather than executed automatically.

Future:

```bash
macroscope apply --interactive plan.json
```

Execution modes:

- `DryRun`: print exactly what would happen
- `Interactive`: ask before each action
- `Apply`: execute selected actions from an explicit plan file

## Action categories

### Safe/read-only actions

- Open path in Finder
- Open relevant settings panel
- Print package-manager command
- Generate Markdown/JSON plan

### Low-risk cleanup actions

- Remove broken symlink
- Move standalone stale binary to Trash
- Remove generated report/cache owned by Macroscope

### Medium-risk migration actions

- Install Homebrew replacement for standalone Intel CLI
- Rebuild Cargo-installed tool as native ARM
- Reinstall npm global under current Node
- Reinstall cask app as universal/ARM

### High-risk actions

- Delete app bundles
- Remove app support data
- Remove LaunchAgents/LaunchDaemons
- Remove shell initialization blocks
- Uninstall package-manager packages with dependents

High-risk actions should start as manual instructions only.

## Initial ActionPlan milestone

Implement a read-only `ActionPlan` model and `macroscope plan` command.

Initial generated actions:

1. For Intel-only standalone binaries in `/usr/local/bin`:
   - Suggest native Homebrew replacement when known.
   - Suggest moving the stale binary to Trash after replacement/verification.

2. For duplicate app bundle IDs:
   - Generate manual review actions, not deletion.

3. For duplicate PATH entries:
   - Generate manual shell-config review action.

4. For ARM Macs using Intel Homebrew:
   - Generate Homebrew migration guidance.

## Suggested implementation model

```rust
struct ActionPlan {
    summary: ActionPlanSummary,
    actions: Vec<PlannedAction>,
}

struct PlannedAction {
    id: String,
    title: String,
    rationale: String,
    confidence: Confidence,
    risk: ActionRisk,
    destructive: bool,
    kind: ActionKind,
}

enum ActionKind {
    MoveToTrash { path: PathBuf },
    BrewInstall { package: String },
    Manual { instructions: String },
}
```

## Near-term coding tasks

- [x] Pretty `scan` output
- [x] Initial `tui`
- [x] Add `ActionPlan` types
- [x] Add `plan` command
- [x] Add Markdown rendering for plans
- [x] Show plan summary in TUI
- [x] Add `explain` command
- [x] Add dry-run executor
- [x] Add safe Trash implementation
