use macroscope::apply::{dry_run_action_plan, validate_action_plan, validate_trash_path};
use macroscope::correlation::build_correlation_graph;
use macroscope::decisions::{apply_decisions, load_decisions_from};
use macroscope::hygiene::stable_service_signature;
use macroscope::model::*;
use macroscope::plan::generate_action_plan;
use macroscope::snapshot::{diff_reports, save_snapshot, verify_reports};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn finding(id: &str) -> Finding {
    Finding {
        id: id.into(),
        category: FindingCategory::Persistence,
        severity: Severity::Warn,
        confidence: Confidence::High,
        title: id.into(),
        detail: id.into(),
        evidence: vec![],
    }
}

fn report(findings: Vec<Finding>) -> Report {
    Report {
        schema_version: 3,
        collected_at_unix: 100,
        system: SystemReport {
            arch: "arm64".into(),
            macos: "15".into(),
            shell: None,
        },
        homebrew: HomebrewReport::default(),
        apps: AppsReport {
            scanned_roots: vec![],
            apps: vec![],
            duplicate_bundle_ids: BTreeMap::new(),
            errors: vec![],
            root_errors: vec![],
        },
        persistence: PersistenceReport::default(),
        runtime: RuntimeReport::default(),
        correlations: CorrelationGraph::default(),
        local_bins: vec![],
        local_bin_errors: vec![],
        path: PathReport {
            entries: vec![],
            duplicates: BTreeMap::new(),
            opt_homebrew_before_usr_local: None,
        },
        dev_tools: DevToolsReport::default(),
        findings,
        suppressed_findings: vec![],
        decision_errors: vec![],
    }
}

#[test]
fn diffs_and_verifies_stable_finding_ids() {
    let mut before = report(vec![finding("persistent-launch-item:test")]);
    before.findings[0].evidence = vec!["/Library/LaunchDaemons/test.plist".into()];
    let mut after = report(vec![finding("persistent-launch-item:new")]);
    after.collected_at_unix = 200;

    let diff = diff_reports(&before, &after);
    assert_eq!(diff.resolved_findings, ["persistent-launch-item:test"]);
    assert_eq!(diff.added_findings, ["persistent-launch-item:new"]);

    let verification = verify_reports(&before, &after, &[]);
    assert!(verification.passed);
    assert_eq!(verification.resolved, ["persistent-launch-item:test"]);
    assert_eq!(
        verification.new_priority_findings,
        ["persistent-launch-item:new"]
    );

    let unknown = verify_reports(&before, &after, &["mistyped-finding".into()]);
    assert!(!unknown.passed);
    assert_eq!(unknown.unknown_targets, ["mistyped-finding"]);

    let mut incomplete = after;
    incomplete
        .persistence
        .errors
        .push("/Library/LaunchDaemons/test.plist: malformed plist".into());
    let inconclusive = verify_reports(
        &before,
        &incomplete,
        &["persistent-launch-item:test".into()],
    );
    assert!(!inconclusive.passed);
    assert_eq!(inconclusive.inconclusive_errors.len(), 1);
    assert!(inconclusive.resolved.is_empty());
    assert_eq!(
        inconclusive.inconclusive_targets,
        ["persistent-launch-item:test"]
    );
    let mut mixed_before = before.clone();
    let mut architecture = finding("intel-app:/Applications/Old.app");
    architecture.category = FindingCategory::Architecture;
    mixed_before.findings.push(architecture);
    let mut package = finding("homebrew-outdated");
    package.category = FindingCategory::PackageManager;
    mixed_before.findings.push(package);
    incomplete.homebrew.error = Some("brew unavailable".into());
    let inconclusive_diff = diff_reports(&mixed_before, &incomplete);
    assert_eq!(
        inconclusive_diff.resolved_findings,
        ["intel-app:/Applications/Old.app"]
    );
    assert_eq!(
        inconclusive_diff.inconclusive_findings,
        ["homebrew-outdated", "persistent-launch-item:test"]
    );
    assert_eq!(inconclusive_diff.inconclusive_errors.len(), 1);
}

#[test]
fn orphan_helper_verification_is_inconclusive_when_app_roots_fail() {
    let mut orphan = finding("orphaned-privileged-helper:system-daemon:test");
    orphan.category = FindingCategory::Persistence;
    orphan.evidence = vec!["/Library/LaunchDaemons/test.plist".into()];
    let before = report(vec![orphan]);
    let mut after = report(vec![]);
    after
        .apps
        .root_errors
        .push("/Applications: failed to inspect root: permission denied".into());

    let verification = verify_reports(
        &before,
        &after,
        &["orphaned-privileged-helper:system-daemon:test".into()],
    );
    assert!(!verification.passed);
    assert_eq!(
        verification.inconclusive_targets,
        ["orphaned-privileged-helper:system-daemon:test"]
    );
    assert!(
        verification
            .inconclusive_errors
            .iter()
            .any(|error| error.starts_with("applications:"))
    );
}

#[test]
fn interpreter_module_services_have_distinct_stable_signatures() {
    let process = |command: &str| ProcessEntry {
        pid: 99,
        ppid: 1,
        executable: Some("/usr/bin/python3".into()),
        elapsed_seconds: 30,
        state: "S".into(),
        cpu_percent: 0.0,
        memory_percent: 0.0,
        command: command.into(),
    };
    assert_ne!(
        stable_service_signature(&process("python3 -m uvicorn app_a:app")),
        stable_service_signature(&process("python3 -m uvicorn app_b:app")),
    );
    assert_ne!(
        stable_service_signature(&process("python3 /srv/a.py -m worker")),
        stable_service_signature(&process("python3 /srv/b.py -m worker")),
    );
}

#[test]
fn verification_requires_a_targeted_wildcard_listener_to_close() {
    let process = ProcessEntry {
        pid: 99,
        ppid: 1,
        executable: Some("/srv/example-server".into()),
        elapsed_seconds: 30,
        state: "S".into(),
        cpu_percent: 0.0,
        memory_percent: 0.0,
        command: "/srv/example-server --serve".into(),
    };
    let signature = stable_service_signature(&process);
    let mut target = finding("old-detached-listener:fixture:all-8080");
    target.category = FindingCategory::Runtime;
    target.evidence = vec![
        format!("service_signature={signature}"),
        process.command.clone(),
        "*:8080".into(),
    ];
    let before = report(vec![target]);
    let mut after = report(vec![]);
    after.runtime.processes.push(process);
    after.runtime.listeners.push(ListenerEntry {
        pid: 99,
        command: Some("example-server".into()),
        endpoint: "*:8080".into(),
        port: Some(8080),
        wildcard: true,
        loopback: false,
    });
    let verification = verify_reports(&before, &after, &[]);
    assert!(!verification.passed);
    assert_eq!(
        verification.remaining,
        ["old-detached-listener:fixture:all-8080"]
    );
    after.runtime.listeners[0].wildcard = false;
    after.runtime.listeners[0].loopback = true;
    after.runtime.listeners[0].endpoint = "127.0.0.1:8080".into();
    assert!(!verify_reports(&before, &after, &[]).passed);

    let mut browser = finding("detached-agent-browser-processes");
    browser.category = FindingCategory::Runtime;
    let browser_before = report(vec![browser]);
    let mut browser_after = report(vec![]);
    browser_after.runtime.processes.push(ProcessEntry {
        pid: 100,
        ppid: 1,
        executable: Some("/tmp/agent-browser-darwin".into()),
        elapsed_seconds: 1,
        state: "S".into(),
        cpu_percent: 0.0,
        memory_percent: 0.0,
        command: "/tmp/agent-browser-darwin".into(),
    });
    let verification = verify_reports(&browser_before, &browser_after, &[]);
    assert!(!verification.passed);
    assert_eq!(verification.remaining, ["detached-agent-browser-processes"]);
}

#[test]
fn decision_load_errors_are_not_treated_as_an_empty_store() {
    let directory = std::env::temp_dir().join(format!(
        "macroscope-decisions-directory-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    assert!(load_decisions_from(&directory).is_err());
    assert!(
        load_decisions_from(&directory.join("missing.json"))
            .unwrap()
            .is_empty()
    );
    let unsupported = directory.join("unsupported.json");
    std::fs::write(&unsupported, r#"{"schema_version":2,"decisions":[]}"#).unwrap();
    assert!(load_decisions_from(&unsupported).is_err());
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn keep_ignore_and_active_snooze_suppress_findings() {
    let records = vec![
        DecisionRecord {
            finding_id: "persistent-launch-item:test".into(),
            decision: DecisionKind::Keep,
            reason: Some("intentional".into()),
            created_at_unix: 1,
            until_unix: None,
        },
        DecisionRecord {
            finding_id: "detached-agent-browser-processes".into(),
            decision: DecisionKind::Ignore,
            reason: None,
            created_at_unix: 1,
            until_unix: None,
        },
    ];
    let (active, suppressed) = apply_decisions(
        vec![
            finding("persistent-launch-item:test"),
            finding("other"),
            finding("detached-agent-browser-processes"),
        ],
        &records,
    );
    assert_eq!(active.len(), 2);
    assert_eq!(active[0].id, "other");
    assert_eq!(active[1].id, "detached-agent-browser-processes");
    assert_eq!(suppressed.len(), 1);

    let before = report(vec![finding("persistent-launch-item:test")]);
    let mut after = report(vec![]);
    after.suppressed_findings = suppressed;
    let verification = verify_reports(&before, &after, &[]);
    assert!(
        !verification.passed,
        "a decision is not remediation evidence"
    );
    assert_eq!(verification.remaining, ["persistent-launch-item:test"]);
}

#[test]
fn does_not_plan_actions_for_absent_or_suppressed_source_findings() {
    let mut state = report(vec![]);
    state.local_bins.push(BinEntry {
        path: "/usr/local/bin/old-tool".into(),
        kind: "file".into(),
        arch: Some("x86_64 Mach-O".into()),
        target: None,
        owner: Some("standalone/manual /usr/local/bin".into()),
    });
    assert!(generate_action_plan(&state).actions.is_empty());

    state.local_bins[0].path = "/usr/local/bin/foo+bar".into();
    state.local_bins.push(BinEntry {
        path: "/usr/local/bin/foo-bar".into(),
        kind: "file".into(),
        arch: Some("x86_64 Mach-O".into()),
        target: None,
        owner: Some("standalone/manual /usr/local/bin".into()),
    });
    state.findings = vec![
        finding("intel-local-bin:/usr/local/bin/foo+bar"),
        finding("intel-local-bin:/usr/local/bin/foo-bar"),
    ];
    let plan = generate_action_plan(&state);
    let ids: BTreeSet<&str> = plan
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    assert_eq!(ids.len(), plan.actions.len());

    for (index, name) in ["aws", "aws_completer"].iter().enumerate() {
        state.local_bins[index].path = PathBuf::from(format!("/usr/local/bin/{name}"));
    }
    state.findings = vec![finding("intel-local-bin:/usr/local/bin/aws_completer")];
    let plan = generate_action_plan(&state);
    assert!(plan.actions.iter().any(|action| {
        matches!(&action.kind, ActionKind::BrewInstall { package } if package == "awscli")
    }));
}

#[test]
fn rejects_arbitrary_or_uncontrolled_trash_actions() {
    assert!(validate_trash_path(Path::new("/System/Library/test")).is_err());
    assert!(validate_trash_path(Path::new("/Users/example/file")).is_err());
    assert!(validate_trash_path(Path::new("/usr/local/bin/../etc/passwd")).is_err());
    assert!(validate_trash_path(Path::new("/usr/local/bin/old-tool")).is_ok());

    let path = PathBuf::from("/usr/local/bin/old-tool");
    let plan = ActionPlan {
        schema_version: 2,
        summary: ActionPlanSummary {
            total: 1,
            destructive: 1,
            low_risk: 0,
            medium_risk: 1,
            high_risk: 0,
        },
        actions: vec![PlannedAction {
            id: "trash-old-tool".into(),
            title: "Trash old tool".into(),
            rationale: "fixture".into(),
            confidence: Confidence::High,
            risk: ActionRisk::Medium,
            destructive: true,
            kind: ActionKind::MoveToTrash { path: path.clone() },
            controls: ActionControls {
                requires_root: false,
                source_finding_id: None,
                expected_file: Some(FileIdentity {
                    device: 1,
                    inode: 2,
                    size: 3,
                    modified_seconds: 4,
                    modified_nanoseconds: 5,
                }),
                provenance: vec!["fixture scan".into()],
                preconditions: vec![ActionCheck {
                    description: "exists".into(),
                    kind: ActionCheckKind::PathExists { path: path.clone() },
                }],
                undo: vec![ActionStep {
                    description: "restore from Trash".into(),
                    command: None,
                }],
                verification: vec![ActionCheck {
                    description: "absent".into(),
                    kind: ActionCheckKind::PathAbsent { path },
                }],
            },
        }],
    };
    assert!(validate_action_plan(&plan).is_ok());
    let mut invalid = plan;
    invalid.summary.total = 0;
    assert!(dry_run_action_plan(&invalid).is_err());
}

#[test]
fn snapshot_write_does_not_follow_existing_symlinks() {
    let root = std::env::temp_dir().join(format!("macroscope-atomic-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let victim = root.join("victim");
    let snapshot = root.join("snapshot.json");
    std::fs::write(&victim, "do-not-overwrite").unwrap();
    symlink(&victim, &snapshot).unwrap();

    save_snapshot(&snapshot, &report(vec![])).unwrap();
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "do-not-overwrite"
    );
    assert!(
        !std::fs::symlink_metadata(&snapshot)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn correlates_launch_process_listener_executable_and_homebrew_package() {
    let program = PathBuf::from("/opt/homebrew/Cellar/demo/1.0/bin/demo");
    let persistence = PersistenceReport {
        launch_items: vec![LaunchItem {
            path: PathBuf::from("/Users/example/Library/LaunchAgents/com.example.demo.plist"),
            label: "com.example.demo".into(),
            scope: LaunchItemScope::UserAgent,
            program: Some(program.clone()),
            program_from_arguments: true,
            program_arguments: vec![program.display().to_string(), "--serve".into()],
            translocation_target: None,
            program_exists: Some(true),
            run_at_load: true,
            keep_alive: true,
            associated_bundle_ids: vec!["com.example.demo".into()],
            parent_app_present: None,
            parent_product: None,
        }],
        errors: vec![],
    };
    let runtime = RuntimeReport {
        processes: vec![ProcessEntry {
            pid: 42,
            ppid: 1,
            executable: Some(program.clone()),
            elapsed_seconds: 100,
            state: "S".into(),
            cpu_percent: 0.0,
            memory_percent: 0.0,
            command: format!("{} --serve", program.display()),
        }],
        listeners: vec![ListenerEntry {
            pid: 42,
            command: Some("demo".into()),
            endpoint: "*:8080".into(),
            port: Some(8080),
            wildcard: true,
            loopback: false,
        }],
        errors: vec![],
    };
    let graph = build_correlation_graph(
        &AppsReport {
            scanned_roots: vec![],
            apps: vec![
                AppEntry {
                    path: "/Applications/Demo.app".into(),
                    name: Some("Demo".into()),
                    bundle_id: Some("com.example.demo".into()),
                    version: None,
                    executable: None,
                    executable_arch: None,
                    scan_error: None,
                },
                AppEntry {
                    path: "/Users/example/Applications/Demo.app".into(),
                    name: Some("Demo copy".into()),
                    bundle_id: Some("com.example.demo".into()),
                    version: None,
                    executable: None,
                    executable_arch: None,
                    scan_error: None,
                },
            ],
            duplicate_bundle_ids: BTreeMap::new(),
            errors: vec![],
            root_errors: vec![],
        },
        &persistence,
        &runtime,
        &[],
    );
    assert!(graph.edges.iter().any(|edge| edge.relation == "runs-as"));
    assert!(graph.edges.iter().any(|edge| edge.relation == "listens-on"));
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| { node.kind == EvidenceNodeKind::Package && node.label == "demo" })
    );
    assert_eq!(
        graph
            .nodes
            .iter()
            .filter(|node| node.kind == EvidenceNodeKind::Application)
            .count(),
        2,
        "duplicate bundle IDs must retain concrete app paths"
    );
}
