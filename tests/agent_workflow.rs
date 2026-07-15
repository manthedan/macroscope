use macroscope::apply::{dry_run_action_plan, validate_action_plan, validate_trash_path};
use macroscope::correlation::{build_correlation_graph, focused_correlation_graph};
use macroscope::decisions::{apply_decisions, load_decisions_from};
use macroscope::hygiene::{launch_item_identity, stable_service_signature};
use macroscope::model::*;
use macroscope::plan::{display_command, generate_action_plan};
use macroscope::snapshot::{diff_reports, managed_snapshot_path, save_snapshot, verify_reports};
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
        pgid: 99,
        uid: 501,
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
        pgid: 99,
        uid: 501,
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
        exposure: ListenerExposure::Wildcard,
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
        pgid: 100,
        uid: 501,
        executable: Some("/tmp/agent-browser-darwin".into()),
        elapsed_seconds: 7 * 60 * 60,
        state: "S".into(),
        cpu_percent: 0.0,
        memory_percent: 0.0,
        command: "/tmp/agent-browser-darwin".into(),
    });
    let verification = verify_reports(&browser_before, &browser_after, &[]);
    assert!(!verification.passed);
    assert_eq!(verification.remaining, ["detached-agent-browser-processes"]);

    browser_after.runtime.processes.clear();
    browser_after.runtime.errors = vec!["lsof failed: permission denied".into()];
    assert!(verify_reports(&browser_before, &browser_after, &[]).passed);

    let mut listener_after = report(vec![]);
    listener_after.runtime.errors = vec!["ps executable collection failed: denied".into()];
    assert!(verify_reports(&before, &listener_after, &[]).passed);
    listener_after.runtime.errors = vec!["lsof failed: permission denied".into()];
    let inconclusive = verify_reports(&before, &listener_after, &[]);
    assert!(!inconclusive.passed);
    assert_eq!(
        inconclusive.inconclusive_targets,
        ["old-detached-listener:fixture:all-8080"]
    );
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
        schema_version: 3,
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
                recommended_steps: vec![],
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
            pgid: 42,
            uid: 501,
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
            exposure: ListenerExposure::Wildcard,
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

    let finding_id = format!(
        "persistent-launch-item:{}",
        launch_item_identity(&persistence.launch_items[0])
    );
    let mut report = report(vec![finding(&finding_id)]);
    report.persistence = persistence;
    report.runtime = runtime;
    report.correlations = graph;
    let focused = focused_correlation_graph(&report, &finding_id).unwrap();
    assert!(
        focused
            .nodes
            .iter()
            .any(|node| node.kind == EvidenceNodeKind::LaunchItem)
    );
    assert!(
        focused
            .nodes
            .iter()
            .any(|node| node.kind == EvidenceNodeKind::Listener)
    );
}

#[test]
fn plans_exact_launchctl_and_runtime_steps_without_executing_them() {
    let item = LaunchItem {
        path: "/Users/example/Library/LaunchAgents/com.example.service.plist".into(),
        label: "com.example.service".into(),
        scope: LaunchItemScope::UserAgent,
        program: Some("/srv/service".into()),
        program_from_arguments: true,
        program_arguments: vec!["/srv/service".into()],
        translocation_target: None,
        program_exists: Some(true),
        run_at_load: true,
        keep_alive: true,
        associated_bundle_ids: vec![],
        parent_app_present: None,
        parent_product: None,
    };
    let finding_id = format!("persistent-launch-item:{}", launch_item_identity(&item));
    let mut persistence_finding = finding(&finding_id);
    persistence_finding.evidence = vec![item.path.display().to_string()];
    let mut launch_report = report(vec![persistence_finding]);
    launch_report.persistence.launch_items.push(item);
    launch_report.runtime.processes.push(ProcessEntry {
        pid: 41,
        ppid: 1,
        pgid: 41,
        uid: 501,
        executable: Some("/srv/service".into()),
        elapsed_seconds: 100,
        state: "S".into(),
        cpu_percent: 0.0,
        memory_percent: 0.0,
        command: "/srv/service".into(),
    });
    let plan = generate_action_plan(&launch_report);
    let action = plan
        .actions
        .iter()
        .find(|action| action.controls.source_finding_id.as_deref() == Some(&finding_id))
        .unwrap();
    let step = action.controls.recommended_steps.first().unwrap();
    let command = step.command.as_ref().unwrap();
    assert_eq!(command.program, "/bin/launchctl");
    assert_eq!(command.args[0], "bootout");
    assert!(action.controls.undo.iter().any(|step| {
        step.command
            .as_ref()
            .is_some_and(|command| command.args.first().is_some_and(|arg| arg == "bootstrap"))
    }));

    let mut listener_finding = finding("old-detached-listener:fixture:wildcard-8080");
    listener_finding.category = FindingCategory::Runtime;
    listener_finding.evidence = vec![
        "service_signature=fixture".into(),
        "pid=42".into(),
        "ppid=1".into(),
        "pgid=42".into(),
        "port=8080".into(),
        "exposure=Wildcard".into(),
        "/srv/service --serve".into(),
        "*:8080".into(),
    ];
    let mut runtime_report = report(vec![listener_finding]);
    runtime_report.runtime.processes.push(ProcessEntry {
        pid: 42,
        ppid: 1,
        pgid: 42,
        uid: 501,
        executable: Some("/srv/service".into()),
        elapsed_seconds: 90_000,
        state: "S".into(),
        cpu_percent: 0.0,
        memory_percent: 0.0,
        command: "/srv/service --serve".into(),
    });
    runtime_report.findings[0].evidence[0] = format!(
        "service_signature={}",
        stable_service_signature(&runtime_report.runtime.processes[0])
    );
    runtime_report.runtime.listeners.push(ListenerEntry {
        pid: 42,
        command: Some("service".into()),
        endpoint: "*:8080".into(),
        port: Some(8080),
        wildcard: true,
        loopback: false,
        exposure: ListenerExposure::Wildcard,
    });
    let mut duplicate_process = runtime_report.runtime.processes[0].clone();
    duplicate_process.pid = 43;
    runtime_report.runtime.processes.push(duplicate_process);
    runtime_report.runtime.listeners.push(ListenerEntry {
        pid: 43,
        command: Some("service".into()),
        endpoint: "*:8080".into(),
        port: Some(8080),
        wildcard: true,
        loopback: false,
        exposure: ListenerExposure::Wildcard,
    });
    let plan = generate_action_plan(&runtime_report);
    let action = plan.actions.first().unwrap();
    assert_eq!(
        action
            .controls
            .recommended_steps
            .iter()
            .filter(|step| step
                .command
                .as_ref()
                .is_some_and(|command| command.program == "/bin/kill"))
            .count(),
        2
    );
    assert!(
        action
            .controls
            .preconditions
            .iter()
            .any(|check| { matches!(check.kind, ActionCheckKind::ProcessMatches { pid: 42, .. }) })
    );
    assert!(action.controls.recommended_steps.iter().any(|step| {
        step.command.as_ref().is_some_and(|command| {
            command.program == "/bin/kill" && command.args == ["-TERM", "42"]
        })
    }));
    assert!(
        action
            .controls
            .verification
            .iter()
            .any(|check| { matches!(check.kind, ActionCheckKind::PortClosed { port: 8080 }) })
    );
}

#[test]
fn runtime_plans_use_structured_state_not_capped_or_command_contaminated_evidence() {
    let mut browser = finding("detached-agent-browser-processes");
    browser.category = FindingCategory::Runtime;
    browser.evidence = vec!["pid=1 command=only-one-rendered-item".into()];
    let mut browser_report = report(vec![browser]);
    for pid in 100..113 {
        browser_report.runtime.processes.push(ProcessEntry {
            pid,
            ppid: 1,
            pgid: pid,
            uid: 501,
            executable: Some("/tmp/agent-browser-darwin".into()),
            elapsed_seconds: 30_000,
            state: "S".into(),
            cpu_percent: 0.0,
            memory_percent: 0.0,
            command: "/tmp/agent-browser-darwin".into(),
        });
    }
    browser_report.runtime.processes.push(ProcessEntry {
        pid: 500,
        ppid: 1,
        pgid: 500,
        uid: 501,
        executable: Some("/tmp/agent-browser-darwin".into()),
        elapsed_seconds: 100,
        state: "S".into(),
        cpu_percent: 0.0,
        memory_percent: 0.0,
        command: "/tmp/agent-browser-darwin".into(),
    });
    let plan = generate_action_plan(&browser_report);
    assert_eq!(plan.actions[0].controls.recommended_steps.len(), 13);
    let focused =
        focused_correlation_graph(&browser_report, "detached-agent-browser-processes").unwrap();
    assert!(!focused.nodes.iter().any(|node| node.id == "process:500"));

    let mut zombie = finding("zombie-processes");
    zombie.category = FindingCategory::Runtime;
    zombie.evidence = vec![
        "pid=200 ppid=201 command=tool recommended_target_pid=999 recommended_target_pid=201"
            .into(),
    ];
    let mut zombie_report = report(vec![zombie]);
    zombie_report.runtime.processes.extend([
        ProcessEntry {
            pid: 200,
            ppid: 201,
            pgid: 201,
            uid: 501,
            executable: None,
            elapsed_seconds: 10,
            state: "Z".into(),
            cpu_percent: 0.0,
            memory_percent: 0.0,
            command: "<defunct>".into(),
        },
        ProcessEntry {
            pid: 201,
            ppid: 1,
            pgid: 201,
            uid: 501,
            executable: Some("/srv/parent".into()),
            elapsed_seconds: 10,
            state: "S".into(),
            cpu_percent: 0.0,
            memory_percent: 0.0,
            command: "/srv/parent recommended_target_pid=999".into(),
        },
        ProcessEntry {
            pid: 202,
            ppid: 1,
            pgid: 1,
            uid: 501,
            executable: None,
            elapsed_seconds: 10,
            state: "Z".into(),
            cpu_percent: 0.0,
            memory_percent: 0.0,
            command: "<defunct>".into(),
        },
        ProcessEntry {
            pid: 1,
            ppid: 0,
            pgid: 1,
            uid: 0,
            executable: Some("/sbin/launchd".into()),
            elapsed_seconds: 10,
            state: "S".into(),
            cpu_percent: 0.0,
            memory_percent: 0.0,
            command: "/sbin/launchd".into(),
        },
        ProcessEntry {
            pid: 999,
            ppid: 1,
            pgid: 999,
            uid: 501,
            executable: Some("/srv/unrelated".into()),
            elapsed_seconds: 10,
            state: "S".into(),
            cpu_percent: 0.0,
            memory_percent: 0.0,
            command: "/srv/unrelated".into(),
        },
    ]);
    let plan = generate_action_plan(&zombie_report);
    let argv = &plan.actions[0]
        .controls
        .recommended_steps
        .iter()
        .find_map(|step| step.command.as_ref())
        .unwrap()
        .args;
    assert_eq!(argv, &["-TERM", "201"]);
    assert!(
        !plan.actions[0]
            .controls
            .recommended_steps
            .iter()
            .any(|step| {
                step.command
                    .as_ref()
                    .is_some_and(|command| command.args == ["-TERM", "1"])
            })
    );
    assert!(
        plan.actions[0]
            .controls
            .recommended_steps
            .iter()
            .any(|step| {
                step.command.is_none() && step.description.contains("protected/system")
            })
    );
    let focused = focused_correlation_graph(&zombie_report, "zombie-processes").unwrap();
    assert!(focused.nodes.iter().any(|node| node.id == "process:200"));
    assert!(focused.nodes.iter().any(|node| node.id == "process:201"));
}

#[test]
fn displayed_remediation_argv_is_json_not_shell_text() {
    let command = CommandSpec {
        program: "/bin/launchctl".into(),
        args: vec!["bootout".into(), "gui/501/$(touch /tmp/nope)`x`".into()],
        requires_root: false,
    };
    let rendered = display_command(&command);
    let parsed: Vec<String> = serde_json::from_str(&rendered).unwrap();
    assert_eq!(
        parsed,
        vec![
            command.program,
            command.args[0].clone(),
            command.args[1].clone()
        ]
    );
}

#[test]
fn focused_graph_synthesizes_an_unconnected_app_node() {
    let path = "/Applications/Offline Intel.app";
    let mut report = report(vec![finding(&format!("intel-app:{path}"))]);
    report.apps.apps.push(AppEntry {
        path: path.into(),
        name: Some("Offline Intel".into()),
        bundle_id: Some("example.offline-intel".into()),
        version: Some("1.0".into()),
        executable: None,
        executable_arch: Some("x86_64".into()),
        scan_error: None,
    });
    let graph = focused_correlation_graph(&report, &format!("intel-app:{path}")).unwrap();
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(graph.nodes[0].kind, EvidenceNodeKind::Application);
}

#[test]
fn private_create_new_writes_do_not_replace_a_winner() {
    let dir =
        std::env::temp_dir().join(format!("macroscope-create-new-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("baseline.json");
    let first_path = path.clone();
    let second_path = path.clone();
    let first = std::thread::spawn(move || {
        macroscope::util::atomic_write_private_new(&first_path, b"first")
    });
    let second = std::thread::spawn(move || {
        macroscope::util::atomic_write_private_new(&second_path, b"second")
    });
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    let contents = std::fs::read(&path).unwrap();
    assert!(contents == b"first" || contents == b"second");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn managed_snapshot_names_reject_path_traversal() {
    assert!(managed_snapshot_path("post-cleanup").is_ok());
    assert!(managed_snapshot_path("../escape").is_err());
    assert!(managed_snapshot_path("nested/name").is_err());
}
