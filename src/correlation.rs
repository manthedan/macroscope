use crate::model::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub fn build_correlation_graph(
    apps: &AppsReport,
    persistence: &PersistenceReport,
    runtime: &RuntimeReport,
    local_bins: &[BinEntry],
) -> CorrelationGraph {
    let mut nodes = BTreeMap::<String, EvidenceNode>::new();
    let mut edges = Vec::<EvidenceEdge>::new();
    let mut edge_keys = BTreeSet::new();

    for item in &persistence.launch_items {
        let launch_id = format!("launch:{}", crate::hygiene::launch_item_identity(item));
        add_node(
            &mut nodes,
            launch_id.clone(),
            EvidenceNodeKind::LaunchItem,
            item.label.clone(),
            [
                ("path", item.path.display().to_string()),
                ("scope", format!("{:?}", item.scope)),
            ],
        );

        if let Some(program) = &item.program {
            let executable_id = executable_node(&mut nodes, program);
            add_edge(
                &mut edges,
                &mut edge_keys,
                &launch_id,
                &executable_id,
                "launches",
                Confidence::High,
            );
            connect_executable_provenance(
                &mut nodes,
                &mut edges,
                &mut edge_keys,
                &executable_id,
                program,
                apps,
                local_bins,
            );
        }

        for app in apps.apps.iter().filter(|app| {
            app.bundle_id
                .as_ref()
                .is_some_and(|id| item.associated_bundle_ids.contains(id))
        }) {
            let app_id = app_node(&mut nodes, app);
            add_edge(
                &mut edges,
                &mut edge_keys,
                &launch_id,
                &app_id,
                "owned-by",
                Confidence::High,
            );
        }

        if let Some(parent) = &item.parent_product
            && let Some(app) = apps
                .apps
                .iter()
                .find(|app| app.path.display().to_string() == *parent)
        {
            let app_id = app_node(&mut nodes, app);
            add_edge(
                &mut edges,
                &mut edge_keys,
                &launch_id,
                &app_id,
                "owned-by",
                Confidence::Medium,
            );
        }

        for process in runtime.processes.iter().filter(|process| {
            crate::hygiene::process_matches_launch_item(
                item,
                &process.command,
                process.executable.as_deref(),
            )
        }) {
            let process_id = process_node(&mut nodes, process);
            add_edge(
                &mut edges,
                &mut edge_keys,
                &launch_id,
                &process_id,
                "runs-as",
                Confidence::High,
            );
            if let Some(executable) = process.executable.as_ref().or(item.program.as_ref()) {
                let executable_id = executable_node(&mut nodes, executable);
                add_edge(
                    &mut edges,
                    &mut edge_keys,
                    &process_id,
                    &executable_id,
                    "executable",
                    Confidence::High,
                );
                connect_executable_provenance(
                    &mut nodes,
                    &mut edges,
                    &mut edge_keys,
                    &executable_id,
                    executable,
                    apps,
                    local_bins,
                );
            }
            connect_process_listeners(
                &mut nodes,
                &mut edges,
                &mut edge_keys,
                &process_id,
                process.pid,
                runtime,
            );
        }
    }

    for listener in &runtime.listeners {
        let Some(process) = runtime
            .processes
            .iter()
            .find(|process| process.pid == listener.pid)
        else {
            continue;
        };
        let process_id = process_node(&mut nodes, process);
        connect_process_listeners(
            &mut nodes,
            &mut edges,
            &mut edge_keys,
            &process_id,
            process.pid,
            runtime,
        );
        if let Some(executable) = infer_process_executable(process, persistence) {
            let executable_id = executable_node(&mut nodes, &executable);
            add_edge(
                &mut edges,
                &mut edge_keys,
                &executable_id,
                &process_id,
                "executes-as",
                Confidence::Medium,
            );
            connect_executable_provenance(
                &mut nodes,
                &mut edges,
                &mut edge_keys,
                &executable_id,
                &executable,
                apps,
                local_bins,
            );
        }
    }

    CorrelationGraph {
        nodes: nodes.into_values().collect(),
        edges,
    }
}

fn connect_process_listeners(
    nodes: &mut BTreeMap<String, EvidenceNode>,
    edges: &mut Vec<EvidenceEdge>,
    edge_keys: &mut BTreeSet<String>,
    process_id: &str,
    pid: u32,
    runtime: &RuntimeReport,
) {
    for listener in runtime.listeners.iter().filter(|entry| entry.pid == pid) {
        let listener_id = format!("listener:{pid}:{}", listener.endpoint);
        add_node(
            nodes,
            listener_id.clone(),
            EvidenceNodeKind::Listener,
            listener.endpoint.clone(),
            [
                ("pid", pid.to_string()),
                ("wildcard", listener.wildcard.to_string()),
                ("exposure", format!("{:?}", listener.exposure)),
            ],
        );
        add_edge(
            edges,
            edge_keys,
            process_id,
            &listener_id,
            "listens-on",
            Confidence::High,
        );
    }
}

fn connect_executable_provenance(
    nodes: &mut BTreeMap<String, EvidenceNode>,
    edges: &mut Vec<EvidenceEdge>,
    edge_keys: &mut BTreeSet<String>,
    executable_id: &str,
    executable: &Path,
    apps: &AppsReport,
    local_bins: &[BinEntry],
) {
    if let Some(app) = apps
        .apps
        .iter()
        .find(|app| executable.starts_with(&app.path))
    {
        let app_id = app_node(nodes, app);
        add_edge(
            edges,
            edge_keys,
            executable_id,
            &app_id,
            "provided-by",
            Confidence::High,
        );
    }

    if let Some((manager, package)) = inferred_package(executable) {
        let package_id = format!("package:{manager}:{package}");
        add_node(
            nodes,
            package_id.clone(),
            EvidenceNodeKind::Package,
            package,
            [("manager", manager)],
        );
        add_edge(
            edges,
            edge_keys,
            executable_id,
            &package_id,
            "provided-by",
            Confidence::High,
        );
    } else if let Some(bin) = local_bins.iter().find(|bin| bin.path == executable)
        && let Some(owner) = &bin.owner
    {
        let package_id = format!("package:owner:{owner}");
        add_node(
            nodes,
            package_id.clone(),
            EvidenceNodeKind::Package,
            owner.clone(),
            [("manager", "inferred".to_string())],
        );
        add_edge(
            edges,
            edge_keys,
            executable_id,
            &package_id,
            "provided-by",
            Confidence::Medium,
        );
    }
}

fn infer_process_executable(
    process: &ProcessEntry,
    persistence: &PersistenceReport,
) -> Option<PathBuf> {
    if let Some(executable) = &process.executable {
        return Some(executable.clone());
    }
    if let Some(program) = persistence.launch_items.iter().find_map(|item| {
        crate::hygiene::process_matches_launch_item(
            item,
            &process.command,
            process.executable.as_deref(),
        )
        .then_some(item.program.as_ref())
        .flatten()
    }) {
        return Some(program.clone());
    }
    process
        .command
        .split_whitespace()
        .next()
        .filter(|value| value.starts_with('/'))
        .map(PathBuf::from)
}

fn inferred_package(path: &Path) -> Option<(String, String)> {
    let components: Vec<String> = path
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    if let Some(index) = components.iter().position(|part| part == "Cellar")
        && let Some(package) = components.get(index + 1)
    {
        return Some(("homebrew".into(), package.clone()));
    }
    if let Some(index) = components.iter().position(|part| part == "node_modules")
        && let Some(first) = components.get(index + 1)
    {
        let package = if first.starts_with('@') {
            components
                .get(index + 2)
                .map(|second| format!("{first}/{second}"))
                .unwrap_or_else(|| first.clone())
        } else {
            first.clone()
        };
        return Some(("npm".into(), package));
    }
    if let Some(index) = components.iter().position(|part| part == "projects")
        && let Some(project) = components.get(index + 1)
    {
        return Some(("project".into(), project.clone()));
    }
    None
}

fn process_node(nodes: &mut BTreeMap<String, EvidenceNode>, process: &ProcessEntry) -> String {
    let id = format!("process:{}", process.pid);
    add_node(
        nodes,
        id.clone(),
        EvidenceNodeKind::Process,
        format!("PID {}", process.pid),
        [
            ("command", process.command.clone()),
            (
                "executable",
                process
                    .executable
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
            ),
            ("ppid", process.ppid.to_string()),
            ("pgid", process.pgid.to_string()),
            ("uid", process.uid.to_string()),
            ("elapsed_seconds", process.elapsed_seconds.to_string()),
        ],
    );
    id
}

fn executable_node(nodes: &mut BTreeMap<String, EvidenceNode>, path: &Path) -> String {
    let id = format!("executable:{}", path.display());
    add_node(
        nodes,
        id.clone(),
        EvidenceNodeKind::Executable,
        path.display().to_string(),
        [("path", path.display().to_string())],
    );
    id
}

fn app_node(nodes: &mut BTreeMap<String, EvidenceNode>, app: &AppEntry) -> String {
    let identity = app
        .bundle_id
        .clone()
        .unwrap_or_else(|| "unknown-bundle-id".into());
    let id = format!("application:{identity}:{}", app.path.display());
    add_node(
        nodes,
        id.clone(),
        EvidenceNodeKind::Application,
        app.name.clone().unwrap_or(identity),
        [
            ("path", app.path.display().to_string()),
            ("bundle_id", app.bundle_id.clone().unwrap_or_default()),
        ],
    );
    id
}

fn add_node<const N: usize>(
    nodes: &mut BTreeMap<String, EvidenceNode>,
    id: String,
    kind: EvidenceNodeKind,
    label: String,
    attributes: [(&str, String); N],
) {
    nodes.entry(id.clone()).or_insert_with(|| EvidenceNode {
        id,
        kind,
        label,
        attributes: attributes
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    });
}

pub fn focused_correlation_graph(report: &Report, finding_id: &str) -> Option<CorrelationGraph> {
    let finding = report
        .findings
        .iter()
        .chain(report.suppressed_findings.iter().map(|item| &item.finding))
        .find(|finding| finding.id == finding_id)?;
    let mut nodes: BTreeMap<String, EvidenceNode> = report
        .correlations
        .nodes
        .iter()
        .cloned()
        .map(|node| (node.id.clone(), node))
        .collect();
    let mut edges = report.correlations.edges.clone();
    let mut edge_keys: BTreeSet<String> = edges
        .iter()
        .map(|edge| format!("{}\0{}\0{}", edge.from, edge.relation, edge.to))
        .collect();
    let mut process_pids = BTreeSet::new();
    if finding.id == "detached-agent-browser-processes" {
        process_pids.extend(
            report
                .runtime
                .processes
                .iter()
                .filter(|process| {
                    process.ppid == 1
                        && process.elapsed_seconds >= 6 * 60 * 60
                        && (process.command.contains("/.agent-browser/browsers/")
                            || process.command.contains("agent-browser-darwin"))
                })
                .map(|process| process.pid),
        );
    } else if finding.id == "zombie-processes" {
        for process in report
            .runtime
            .processes
            .iter()
            .filter(|process| process.state.contains('Z'))
        {
            process_pids.insert(process.pid);
            process_pids.insert(process.ppid);
        }
    }
    let mut seeds = BTreeSet::new();
    for prefix in [
        "persistent-launch-item:",
        "translocated-launch-item:",
        "orphaned-privileged-helper:",
    ] {
        if let Some(identity) = finding.id.strip_prefix(prefix) {
            seeds.insert(format!("launch:{identity}"));
        }
    }
    for evidence in &finding.evidence {
        if let Some(pid) = trusted_evidence_pid(evidence) {
            process_pids.insert(pid);
        }
    }
    for pid in process_pids {
        let Some(process) = report
            .runtime
            .processes
            .iter()
            .find(|process| process.pid == pid)
        else {
            continue;
        };
        let process_id = process_node(&mut nodes, process);
        seeds.insert(process_id.clone());
        connect_process_listeners(
            &mut nodes,
            &mut edges,
            &mut edge_keys,
            &process_id,
            process.pid,
            &report.runtime,
        );
        if let Some(parent) = report
            .runtime
            .processes
            .iter()
            .find(|parent| parent.pid == process.ppid)
        {
            let parent_id = process_node(&mut nodes, parent);
            add_edge(
                &mut edges,
                &mut edge_keys,
                &process_id,
                &parent_id,
                "child-of",
                Confidence::High,
            );
        }
    }
    for evidence in &finding.evidence {
        for node in nodes.values() {
            if node.label == *evidence
                || node.attributes.values().any(|value| value == evidence)
                || (evidence.starts_with('/')
                    && node
                        .attributes
                        .values()
                        .any(|value| value.contains(evidence)))
            {
                seeds.insert(node.id.clone());
            }
        }
    }
    if let Some(path) = finding.id.strip_prefix("intel-app:") {
        if let Some(app) = report
            .apps
            .apps
            .iter()
            .find(|app| app.path.to_string_lossy() == path)
        {
            seeds.insert(app_node(&mut nodes, app));
        }
        for node in nodes.values() {
            if node
                .attributes
                .get("path")
                .is_some_and(|value| value == path)
            {
                seeds.insert(node.id.clone());
            }
        }
    }

    let graph = CorrelationGraph {
        nodes: nodes.into_values().collect(),
        edges,
    };
    let mut selected = seeds;
    for _ in 0..4 {
        let mut next = selected.clone();
        for edge in &graph.edges {
            if selected.contains(&edge.from) || selected.contains(&edge.to) {
                next.insert(edge.from.clone());
                next.insert(edge.to.clone());
            }
        }
        if next == selected {
            break;
        }
        selected = next;
    }
    Some(CorrelationGraph {
        nodes: graph
            .nodes
            .into_iter()
            .filter(|node| selected.contains(&node.id))
            .collect(),
        edges: graph
            .edges
            .into_iter()
            .filter(|edge| selected.contains(&edge.from) && selected.contains(&edge.to))
            .collect(),
    })
}

fn trusted_evidence_pid(evidence: &str) -> Option<u32> {
    if !evidence
        .split_whitespace()
        .any(|field| field.starts_with("command="))
    {
        return evidence.strip_prefix("pid=")?.parse().ok();
    }
    evidence
        .split_whitespace()
        .take_while(|field| !field.starts_with("command="))
        .find_map(|field| field.strip_prefix("pid="))?
        .parse()
        .ok()
}

pub fn print_correlation_graph(graph: &CorrelationGraph) {
    println!(
        "Macroscope correlation graph: {} nodes, {} edges",
        graph.nodes.len(),
        graph.edges.len()
    );
    let nodes: BTreeMap<&str, &EvidenceNode> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let incoming: BTreeSet<&str> = graph.edges.iter().map(|edge| edge.to.as_str()).collect();
    let roots: Vec<&EvidenceNode> = graph
        .nodes
        .iter()
        .filter(|node| {
            node.kind == EvidenceNodeKind::LaunchItem || !incoming.contains(node.id.as_str())
        })
        .collect();
    for root in roots {
        println!("\n{:?}: {}", root.kind, root.label);
        print_edges(graph, &nodes, &root.id, 1, &mut BTreeSet::new());
    }
}

fn print_edges(
    graph: &CorrelationGraph,
    nodes: &BTreeMap<&str, &EvidenceNode>,
    from: &str,
    depth: usize,
    visited: &mut BTreeSet<String>,
) {
    if depth > 5 || !visited.insert(from.to_string()) {
        return;
    }
    for edge in graph.edges.iter().filter(|edge| edge.from == from) {
        if let Some(node) = nodes.get(edge.to.as_str()) {
            println!(
                "{}→ {}: {} [{:?}]",
                "  ".repeat(depth),
                edge.relation,
                node.label,
                edge.confidence
            );
            print_edges(graph, nodes, &node.id, depth + 1, visited);
        }
    }
}

fn add_edge(
    edges: &mut Vec<EvidenceEdge>,
    keys: &mut BTreeSet<String>,
    from: &str,
    to: &str,
    relation: &str,
    confidence: Confidence,
) {
    let key = format!("{from}\0{relation}\0{to}");
    if keys.insert(key) {
        edges.push(EvidenceEdge {
            from: from.to_string(),
            to: to.to_string(),
            relation: relation.to_string(),
            confidence,
        });
    }
}
