use crate::model::{DecisionKind, DecisionRecord, Finding, SuppressedFinding};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Default)]
struct DecisionStore {
    schema_version: u32,
    decisions: Vec<DecisionRecord>,
}

pub fn default_decision_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("MACROSCOPE_DECISIONS") {
        return Ok(PathBuf::from(path));
    }
    let home = dirs::home_dir().context("cannot locate home directory")?;
    Ok(home.join(".config/macroscope/decisions.json"))
}

pub fn load_decisions() -> Result<Vec<DecisionRecord>> {
    load_decisions_from(&default_decision_path()?)
}

pub fn load_decisions_from(path: &Path) -> Result<Vec<DecisionRecord>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read decision store {}", path.display()));
        }
    };
    let store: DecisionStore = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse decision store {}", path.display()))?;
    if store.schema_version != 1 {
        anyhow::bail!(
            "unsupported decision store schema {} in {}; expected 1",
            store.schema_version,
            path.display()
        );
    }
    let mut finding_ids = BTreeSet::new();
    for record in &store.decisions {
        if record.finding_id.is_empty() || !finding_ids.insert(&record.finding_id) {
            anyhow::bail!(
                "decision store {} contains an empty or duplicate finding ID",
                path.display()
            );
        }
        match record.decision {
            DecisionKind::Snooze
                if record
                    .until_unix
                    .is_none_or(|until| until <= record.created_at_unix) =>
            {
                anyhow::bail!(
                    "snooze decision `{}` in {} has no valid expiry",
                    record.finding_id,
                    path.display()
                );
            }
            DecisionKind::Keep | DecisionKind::Ignore if record.until_unix.is_some() => {
                anyhow::bail!(
                    "non-snooze decision `{}` in {} unexpectedly has an expiry",
                    record.finding_id,
                    path.display()
                );
            }
            _ => {}
        }
    }
    Ok(store.decisions)
}

pub fn record_decision(
    finding_id: String,
    decision: DecisionKind,
    reason: Option<String>,
    snooze_days: Option<u64>,
) -> Result<DecisionRecord> {
    if !durable_decision_allowed(&finding_id) {
        anyhow::bail!(
            "finding `{finding_id}` is aggregate runtime evidence and cannot be durably suppressed"
        );
    }
    let path = default_decision_path()?;
    let mut decisions = load_decisions_from(&path)?;
    let now = now_unix();
    let until_unix = if decision == DecisionKind::Snooze {
        let days = snooze_days.unwrap_or(30);
        if days == 0 {
            anyhow::bail!("snooze duration must be at least one day");
        }
        Some(now.saturating_add(days.saturating_mul(86_400)))
    } else {
        None
    };
    let record = DecisionRecord {
        finding_id: finding_id.clone(),
        decision,
        reason,
        created_at_unix: now,
        until_unix,
    };
    decisions.retain(|item| item.finding_id != finding_id);
    decisions.push(record.clone());
    decisions.sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
    save_decisions(&path, &decisions)?;
    Ok(record)
}

pub fn clear_decision(finding_id: &str) -> Result<bool> {
    let path = default_decision_path()?;
    let mut decisions = load_decisions_from(&path)?;
    let before = decisions.len();
    decisions.retain(|item| item.finding_id != finding_id);
    if decisions.len() != before {
        save_decisions(&path, &decisions)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn apply_decisions(
    findings: Vec<Finding>,
    decisions: &[DecisionRecord],
) -> (Vec<Finding>, Vec<SuppressedFinding>) {
    let now = now_unix();
    let mut active = Vec::new();
    let mut suppressed = Vec::new();
    for finding in findings {
        let decision = decisions.iter().find(|decision| {
            durable_decision_allowed(&finding.id)
                && decision.finding_id == finding.id
                && (decision.decision != DecisionKind::Snooze
                    || decision.until_unix.is_some_and(|until| until > now))
        });
        if let Some(decision) = decision {
            suppressed.push(SuppressedFinding {
                finding,
                decision: decision.clone(),
            });
        } else {
            active.push(finding);
        }
    }
    (active, suppressed)
}

fn durable_decision_allowed(finding_id: &str) -> bool {
    !matches!(
        finding_id,
        "detached-agent-browser-processes" | "zombie-processes"
    )
}

fn save_decisions(path: &Path, decisions: &[DecisionRecord]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let store = DecisionStore {
        schema_version: 1,
        decisions: decisions.to_vec(),
    };
    crate::util::atomic_write_private(path, &serde_json::to_vec_pretty(&store)?)
        .with_context(|| format!("failed to save decision store {}", path.display()))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
