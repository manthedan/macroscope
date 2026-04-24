use crate::model::*;
use crate::plan::generate_action_plan;
use crate::scan::scan;
use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
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

pub fn dry_run_action_plan(plan: &ActionPlan) {
    println!(
        "{} {}",
        "◉".bright_cyan().bold(),
        "Macroscope Apply Dry Run".bright_cyan().bold()
    );
    println!("{}", "No changes will be made.".dimmed());
    println!();

    if plan.actions.is_empty() {
        println!("{}", "No actions to dry-run.".green());
        return;
    }

    for action in &plan.actions {
        print_apply_preview(action, true);
    }
}

pub fn apply_action_plan(plan: &ActionPlan, yes: bool) -> Result<()> {
    if !yes {
        anyhow::bail!(
            "refusing to mutate without --yes; run `macroscope apply --dry-run` first, then `macroscope apply --yes [plan.json]`"
        );
    }

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
        "  Risk: {:?} | Confidence: {:?} | Destructive: {}",
        action.risk, action.confidence, action.destructive
    );
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
