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

Current: pretty read-only audit with terminal scan progress animation.

Planned:

- Better categories and finding IDs
- [x] App versions, architectures, bundle IDs, and paths in reports
- More precise app architecture detection
- Modified/opened dates where available
- Quarantine and code-signing status
- [x] Initial `/usr/local/bin` ownership detection
- [x] Homebrew outdated packages, services, autoremove preview, and cleanup dry-run
- [x] Conda environment and cache inventory
- [x] Go toolchain and GOPATH/bin binary architecture inventory
- Deeper package-manager ownership detection

### `macroscope tui`

Current: interactive dashboard with scan/rescan progress animation, selectable Findings and Plan tabs, plan summary, related actions, action detail browsing, explain modals, dry-run previews, plan export, rescan, and guarded apply controls. Plain `macroscope tui` is read-only; `macroscope tui --apply` enables Move-to-Trash execution only after a dry-run and typed confirmation.

Planned:

- More tabs: Apps, Binaries, Packages
- Search/filter by severity/category/path
- Multi-select action staging
- Scrollable modal/history panes
- Track per-action status in the TUI: pending, dry-run, applied, skipped, failed
- Remove or mark applied actions immediately after successful TUI apply so a rescan is not required for feedback
- Better apply result summaries, including counts for applied/skipped/failed actions
- Let `a` on the Findings tab apply related executable actions using the same guarded flow as Plan actions
- Treat `Enter` as a natural open/explain action for the selected item
- Package-manager action execution after ownership metadata improves

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

Interactive apply now exists in the TUI for executable Move-to-Trash actions:

```bash
macroscope tui --apply
```

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
- Rebuild Go-installed tool as native ARM
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

## Next priorities

1. **Polish TUI apply state**
   - Track dry-run/applied/failed/skipped status per action.
   - Update or remove successfully applied actions in-memory.
   - Improve apply result modals and summaries.
   - Add scroll support for long dry-run/apply/explain modals.
   - Extend Findings-tab apply to related executable actions.

2. **Split the TUI module**
   - `src/tui.rs` is now isolated but still large.
   - Split into `tui/mod.rs`, `tui/state.rs`, `tui/render.rs`, `tui/input.rs`, and `tui/progress.rs` before adding much more TUI complexity.

3. **Improve Go cleanup intelligence**
   - Map known Go binaries to rebuild commands, e.g. `gopls`, `goimports`, `dlv`, `staticcheck`.
   - Group unknown/project-specific Go binaries separately.
   - Prefer native rebuild guidance before deletion.
   - Consider stale unknown binary cleanup only when provenance and PATH risk are clear.

4. **Improve Conda cleanup intelligence**
   - Parse `conda info --envs` style environment details.
   - Identify active/current root and duplicate root installs.
   - Detect Conda shell init/PATH blocks in shell startup files.
   - Generate export/remove guidance, but keep actual removal manual until confidence is high.

5. **Add cautious Homebrew execution paths**
   - Start with clearer/copyable package-manager commands in the TUI.
   - Later add explicit action kinds for `brew cleanup`, `brew autoremove`, and `brew install`.
   - Keep real execution gated by dry-run, plan review, typed confirmation, and ownership confidence.

6. **Add TUI search/filter**
   - `/` search across findings/actions.
   - Severity/category/path filters.
   - `g`/`G` jump to top/bottom.

7. **Deepen app cleanup intelligence**
   - Include app size, last opened/modified dates, quarantine status, signing status, and cask ownership.
   - Improve duplicate app handling.
   - Keep app deletion as Trash-backed and explicitly confirmed.

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
- [x] Add Homebrew cleanup intelligence
- [x] Add CLI and TUI scan progress animations
- [x] Add TUI explain/dry-run/export/rescan controls
- [x] Add guarded TUI apply mode for Move-to-Trash actions
