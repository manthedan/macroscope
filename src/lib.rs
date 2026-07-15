pub mod apply;
pub mod brief;
pub mod correlation;
pub mod decisions;
pub mod findings;
pub mod guide;
pub mod hygiene;
pub mod markdown;
pub mod model;
pub mod output;
pub mod plan;
pub mod scan;
pub mod snapshot;
pub mod util;

#[cfg(test)]
mod tests {
    use super::brief::executable_action_count;
    use super::model::*;
    use super::plan::{action_disposition, related_actions, slugify, summarize_actions};
    use super::scan::{parse_conda_info, parse_npm_packages};
    use super::util::simplify_file_arch;
    use std::path::PathBuf;

    fn planned_action(
        id: &str,
        destructive: bool,
        risk: ActionRisk,
        kind: ActionKind,
    ) -> PlannedAction {
        PlannedAction {
            id: id.into(),
            title: format!("Action {id}"),
            rationale: "test rationale".into(),
            confidence: Confidence::High,
            risk,
            destructive,
            kind,
            controls: ActionControls::default(),
        }
    }

    #[test]
    fn slugify_normalizes_paths_and_symbols() {
        assert_eq!(
            slugify("/usr/local/bin/aws_completer"),
            "usr-local-bin-aws-completer"
        );
        assert_eq!(slugify("  Review: Go/Binary v2!! "), "review-go-binary-v2");
        assert_eq!(slugify("Already-Clean"), "already-clean");
    }

    #[test]
    fn simplify_file_arch_extracts_useful_arch_labels() {
        assert_eq!(
            simplify_file_arch("Mach-O universal binary with 2 architectures: [x86_64] [arm64]"),
            "arm64 x86_64 Mach-O"
        );
        assert_eq!(
            simplify_file_arch("Mach-O 64-bit executable x86_64"),
            "x86_64 Mach-O"
        );
        assert_eq!(
            simplify_file_arch("POSIX shell script text executable"),
            "script"
        );
        assert_eq!(simplify_file_arch("ASCII text"), "text");
    }

    #[test]
    fn parse_npm_packages_sorts_dependencies_and_keeps_versions() {
        let packages = parse_npm_packages(
            r#"{
                "dependencies": {
                    "zeta": { "version": "2.0.0" },
                    "alpha": { "version": "1.0.0" },
                    "noversion": {}
                }
            }"#,
        )
        .expect("npm package JSON should parse");

        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "alpha");
        assert_eq!(packages[0].version.as_deref(), Some("1.0.0"));
        assert_eq!(packages[1].name, "noversion");
        assert_eq!(packages[1].version, None);
        assert_eq!(packages[2].name, "zeta");
    }

    #[test]
    fn parse_conda_info_extracts_prefixes_and_arrays() {
        let tool = ToolVersion {
            path: Some("/opt/anaconda3/bin/conda".into()),
            version: Some("conda 24.7.1".into()),
            error: None,
        };
        let report = parse_conda_info(
            &tool,
            r#"{
                "platform": "osx-arm64",
                "base_prefix": "/opt/anaconda3",
                "active_prefix": "/opt/anaconda3/envs/demo",
                "envs": ["/opt/anaconda3", "/Users/example/miniconda3"],
                "envs_dirs": ["/opt/anaconda3/envs"],
                "pkgs_dirs": ["/opt/anaconda3/pkgs", "/Users/example/.conda/pkgs"]
            }"#,
        )
        .expect("conda info JSON should parse");

        assert_eq!(
            report.conda.path.as_deref(),
            Some("/opt/anaconda3/bin/conda")
        );
        assert_eq!(report.platform.as_deref(), Some("osx-arm64"));
        assert_eq!(report.root_prefix.as_deref(), Some("/opt/anaconda3"));
        assert_eq!(
            report.active_prefix.as_deref(),
            Some("/opt/anaconda3/envs/demo")
        );
        assert_eq!(report.envs.len(), 2);
        assert_eq!(report.envs_dirs, vec!["/opt/anaconda3/envs"]);
        assert_eq!(report.package_caches.len(), 2);
    }

    #[test]
    fn classifies_action_dispositions() {
        let trash = planned_action(
            "trash-old-tool",
            true,
            ActionRisk::Medium,
            ActionKind::MoveToTrash {
                path: PathBuf::from("/usr/local/bin/old-tool"),
            },
        );
        assert_eq!(action_disposition(&trash), ActionDisposition::ApplyNow);

        let manual = planned_action(
            "review-cleanup",
            false,
            ActionRisk::Low,
            ActionKind::Manual {
                instructions: "Review cleanup".into(),
            },
        );
        assert_eq!(action_disposition(&manual), ActionDisposition::Manual);

        let handoff = planned_action(
            "review-owner",
            false,
            ActionRisk::Medium,
            ActionKind::Manual {
                instructions: "Review owner".into(),
            },
        );
        assert_eq!(action_disposition(&handoff), ActionDisposition::Handoff);
    }

    #[test]
    fn finding_ids_resolve_related_actions_directly() {
        let mut action = planned_action(
            "review-persistent-launch-item-user-agent-demo",
            false,
            ActionRisk::Medium,
            ActionKind::Manual {
                instructions: "review".into(),
            },
        );
        action.controls.source_finding_id =
            Some("persistent-launch-item:user-agent:demo:abc".into());
        let summary = summarize_actions(std::slice::from_ref(&action));
        let plan = ActionPlan {
            schema_version: 3,
            summary,
            actions: vec![action],
        };
        assert_eq!(
            related_actions("persistent-launch-item:user-agent:demo:abc", &plan).len(),
            1
        );
    }

    #[test]
    fn summarizes_actions_and_counts_executable_trash_actions() {
        let actions = vec![
            planned_action(
                "trash-old-tool",
                true,
                ActionRisk::Medium,
                ActionKind::MoveToTrash {
                    path: PathBuf::from("/usr/local/bin/old-tool"),
                },
            ),
            planned_action(
                "review-cleanup",
                false,
                ActionRisk::Low,
                ActionKind::Manual {
                    instructions: "Review cleanup".into(),
                },
            ),
            planned_action(
                "manual-risky",
                false,
                ActionRisk::High,
                ActionKind::Manual {
                    instructions: "Review risky action".into(),
                },
            ),
        ];

        let summary = summarize_actions(&actions);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.destructive, 1);
        assert_eq!(summary.low_risk, 1);
        assert_eq!(summary.medium_risk, 1);
        assert_eq!(summary.high_risk, 1);

        let plan = ActionPlan {
            schema_version: 3,
            summary,
            actions,
        };
        assert_eq!(executable_action_count(&plan), 1);
    }
}
