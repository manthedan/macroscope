use crate::model::*;
use crate::plan::{display_command, generate_action_plan, summarize_actions};
use crate::scan::scan;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::process::Command;

pub fn load_or_generate_plan(path: Option<&Path>) -> Result<ActionPlan> {
    if let Some(path) = path {
        let json = fs::read_to_string(path)
            .with_context(|| format!("failed to read action plan {}", path.display()))?;
        let plan = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse action plan JSON {}", path.display()))?;
        Ok(plan)
    } else {
        let report = scan();
        Ok(generate_action_plan(&report))
    }
}

pub fn dry_run_action_plan(plan: &ActionPlan) -> Result<()> {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Apply Dry Run".bright_cyan().bold()
    );
    println!("{}", "No changes will be made.".dimmed());
    println!();

    validate_action_plan(plan).context("plan rejected during dry-run")?;

    if plan.actions.is_empty() {
        println!("{}", "No actions to dry-run.".green());
        return Ok(());
    }

    for action in &plan.actions {
        print_apply_preview(action, true);
    }
    Ok(())
}

pub fn apply_action_plan(plan: &ActionPlan, yes: bool) -> Result<()> {
    if !yes {
        anyhow::bail!(
            "refusing to mutate without --yes; run `macroscope apply --dry-run` first, then `macroscope apply --yes [plan.json]`"
        );
    }
    validate_action_plan(plan)?;
    validate_against_fresh_plan(plan)?;

    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Apply".bright_cyan().bold()
    );
    println!(
        "{}",
        "Mutating mode: only move-to-trash actions are executed; package installs and manual actions are printed."
            .yellow()
            .bold()
    );
    println!();

    if plan.actions.is_empty() {
        println!("{}", "No actions to apply.".green());
        return Ok(());
    }

    for action in &plan.actions {
        match &action.kind {
            ActionKind::MoveToTrash { path } => {
                verify_file_identity(
                    path,
                    action
                        .controls
                        .expected_file
                        .as_ref()
                        .context("automatic action is missing expected file identity")?,
                )?;
                println!("{} {}", "Applying:".bold(), action.title.bold());
                println!("  ID: {}", action.id);
                move_to_trash(path)?;
                println!("  {} {}", "Moved to Trash:".green().bold(), path.display());
                println!();
            }
            ActionKind::BrewInstall { .. } | ActionKind::Manual { .. } => {
                print_apply_preview(action, false);
            }
        }
    }

    Ok(())
}

pub fn print_apply_preview(action: &PlannedAction, dry_run: bool) {
    let prefix = if dry_run { "Would run:" } else { "Skipped:" };
    println!("{} {}", prefix.bold(), action.title.bold());
    println!("  ID: {}", action.id);
    println!(
        "  Risk: {:?} | Confidence: {:?} | Destructive: {} | Root: {}",
        action.risk, action.confidence, action.destructive, action.controls.requires_root
    );
    for precondition in &action.controls.preconditions {
        println!("  Precondition: {}", precondition.description);
    }
    for step in &action.controls.recommended_steps {
        println!("  Reviewed step: {}", step.description);
        if let Some(command) = &step.command {
            println!("    Structured argv: {}", display_command(command));
        }
    }
    for verification in &action.controls.verification {
        println!("  Verify: {}", verification.description);
    }
    for undo in &action.controls.undo {
        println!("  Undo: {}", undo.description);
    }
    match &action.kind {
        ActionKind::MoveToTrash { path } => {
            if dry_run {
                println!("  Would move to Trash: {}", path.display());
            } else {
                println!("  Not moved in this pass: {}", path.display());
            }
        }
        ActionKind::BrewInstall { package } => {
            if dry_run {
                println!("  Would execute: brew install {package}");
            } else {
                println!("  Manual/package-manager action not executed: brew install {package}");
            }
        }
        ActionKind::Manual { instructions } => {
            println!("  Manual instruction: {instructions}");
        }
    }
    println!();
}

pub fn validate_action_plan(plan: &ActionPlan) -> Result<()> {
    if plan.schema_version != 3 {
        anyhow::bail!("unsupported action-plan schema {}", plan.schema_version);
    }
    let expected_summary = summarize_actions(&plan.actions);
    if serde_json::to_value(&expected_summary)? != serde_json::to_value(&plan.summary)? {
        anyhow::bail!("action-plan summary does not match its actions");
    }
    let mut ids = BTreeSet::new();
    for action in &plan.actions {
        if !ids.insert(&action.id) {
            anyhow::bail!("duplicate action ID `{}`", action.id);
        }
        if action.controls.provenance.is_empty() {
            anyhow::bail!("action `{}` has no evidence provenance", action.id);
        }
        if let ActionKind::MoveToTrash { path } = &action.kind {
            validate_trash_path(path)?;
            if action.controls.requires_root {
                anyhow::bail!("automatic action `{}` may not require root", action.id);
            }
            if action.controls.expected_file.is_none() {
                anyhow::bail!(
                    "automatic action `{}` has no expected file identity",
                    action.id
                );
            }
            let guarded = action.controls.preconditions.iter().any(|check| {
                matches!(&check.kind, ActionCheckKind::PathExists { path: expected } if expected == path)
            });
            let verified = action.controls.verification.iter().any(|check| {
                matches!(&check.kind, ActionCheckKind::PathAbsent { path: expected } if expected == path)
            });
            if !guarded || !verified || action.controls.undo.is_empty() {
                anyhow::bail!(
                    "automatic action `{}` lacks matching precondition, verification, or undo metadata",
                    action.id
                );
            }
        }
    }
    Ok(())
}

fn validate_against_fresh_plan(plan: &ActionPlan) -> Result<()> {
    let fresh_report = scan();
    if plan
        .actions
        .iter()
        .any(|action| matches!(action.kind, ActionKind::MoveToTrash { .. }))
        && !fresh_report.decision_errors.is_empty()
    {
        anyhow::bail!(
            "cannot validate automatic actions while decisions are unavailable: {}",
            fresh_report.decision_errors.join("; ")
        );
    }
    let fresh = generate_action_plan(&fresh_report);
    for action in &plan.actions {
        let ActionKind::MoveToTrash { path } = &action.kind else {
            continue;
        };
        let canonical = fresh.actions.iter().find(|candidate| {
            candidate.id == action.id
                && matches!(&candidate.kind, ActionKind::MoveToTrash { path: current } if current == path)
        });
        let matches_fresh = canonical.is_some_and(|candidate| {
            serde_json::to_value(candidate).ok() == serde_json::to_value(action).ok()
        });
        if !matches_fresh {
            anyhow::bail!(
                "automatic action `{}` is not supported by a fresh scan; regenerate the plan",
                action.id
            );
        }
    }
    Ok(())
}

fn verify_file_identity(path: &Path, expected: &FileIdentity) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot revalidate {} before mutation", path.display()))?;
    let actual = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    };
    if &actual != expected {
        anyhow::bail!(
            "refusing to mutate `{}` because the file instance changed after approval",
            path.display()
        );
    }
    Ok(())
}

pub fn validate_trash_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("refusing non-absolute cleanup path `{}`", path.display());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        anyhow::bail!("refusing path traversal in `{}`", path.display());
    }
    if path.parent() != Some(Path::new("/usr/local/bin")) || path.file_name().is_none() {
        anyhow::bail!(
            "refusing `{}`: automatic cleanup is restricted to direct children of /usr/local/bin",
            path.display()
        );
    }
    let approved_parent = fs::symlink_metadata("/usr/local/bin")
        .context("cannot validate automatic cleanup root /usr/local/bin")?;
    if !approved_parent.is_dir() || approved_parent.file_type().is_symlink() {
        anyhow::bail!("refusing automatic cleanup because /usr/local/bin is not a real directory");
    }
    Ok(())
}

pub fn move_to_trash(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot move missing path to Trash: {}", path.display()))?;

    if !metadata.is_dir() {
        return move_to_user_trash(path).or_else(|trash_error| {
            move_to_trash_with_finder(path).with_context(|| {
                format!(
                    "direct ~/.Trash move failed ({trash_error}); Finder trash also failed for {}",
                    path.display()
                )
            })
        });
    }

    match move_to_trash_with_finder(path) {
        Ok(()) => Ok(()),
        Err(finder_error) => move_to_user_trash(path).with_context(|| {
            format!(
                "Finder trash failed ({finder_error}); fallback ~/.Trash move also failed for {}",
                path.display()
            )
        }),
    }
}

pub fn move_to_trash_with_finder(path: &Path) -> Result<()> {
    let script = format!(
        "tell application \"Finder\" to delete POSIX file \"{}\"",
        escape_applescript_string(&path.display().to_string())
    );
    let output = Command::new("osascript").arg("-e").arg(script).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "osascript failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn move_to_user_trash(path: &Path) -> Result<()> {
    let home = dirs::home_dir().context("cannot locate home directory for ~/.Trash fallback")?;
    let trash = home.join(".Trash");
    fs::create_dir_all(&trash).with_context(|| format!("failed to create {}", trash.display()))?;

    let file_name = path
        .file_name()
        .context("cannot move path without a file name to Trash")?;
    let mut destination = trash.join(file_name);
    if destination.exists() || fs::symlink_metadata(&destination).is_ok() {
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "item".into());
        let extension = path.extension().map(|s| s.to_string_lossy().into_owned());
        for idx in 1..1000 {
            let candidate_name = if let Some(extension) = &extension {
                format!("{stem} {idx}.{extension}")
            } else {
                format!("{stem} {idx}")
            };
            let candidate = trash.join(candidate_name);
            if !candidate.exists() && fs::symlink_metadata(&candidate).is_err() {
                destination = candidate;
                break;
            }
        }
    }

    fs::rename(path, &destination).or_else(|err| {
        if err.kind() == ErrorKind::CrossesDevices {
            if path.is_dir() {
                anyhow::bail!(
                    "cannot fallback-trash directory across filesystems: {}",
                    path.display()
                );
            }
            fs::copy(path, &destination)?;
            fs::remove_file(path)?;
            Ok(())
        } else {
            Err(err.into())
        }
    })?;
    Ok(())
}

pub fn escape_applescript_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
