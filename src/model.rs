use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub collected_at_unix: u64,
    pub system: SystemReport,
    pub homebrew: HomebrewReport,
    pub apps: AppsReport,
    pub persistence: PersistenceReport,
    pub runtime: RuntimeReport,
    #[serde(default)]
    pub correlations: CorrelationGraph,
    pub local_bins: Vec<BinEntry>,
    #[serde(default)]
    pub local_bin_errors: Vec<String>,
    pub path: PathReport,
    pub dev_tools: DevToolsReport,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub suppressed_findings: Vec<SuppressedFinding>,
    #[serde(default)]
    pub decision_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReport {
    pub arch: String,
    pub macos: String,
    pub shell: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HomebrewReport {
    pub brew_path: Option<String>,
    pub prefix: Option<String>,
    pub formulae: Vec<String>,
    pub casks: Vec<String>,
    pub leaves: Vec<String>,
    pub outdated_formulae: Vec<String>,
    pub outdated_casks: Vec<String>,
    pub services: Vec<HomebrewService>,
    pub autoremove_preview: Vec<String>,
    pub cleanup_preview: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HomebrewService {
    pub name: String,
    pub status: Option<String>,
    pub user: Option<String>,
    pub file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppsReport {
    pub scanned_roots: Vec<PathBuf>,
    pub apps: Vec<AppEntry>,
    pub duplicate_bundle_ids: BTreeMap<String, Vec<PathBuf>>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub root_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEntry {
    pub path: PathBuf,
    pub name: Option<String>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub executable: Option<PathBuf>,
    pub executable_arch: Option<String>,
    #[serde(default)]
    pub scan_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinEntry {
    pub path: PathBuf,
    pub kind: String,
    pub arch: Option<String>,
    pub target: Option<PathBuf>,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathReport {
    pub entries: Vec<String>,
    pub duplicates: BTreeMap<String, usize>,
    pub opt_homebrew_before_usr_local: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevToolsReport {
    pub node: ToolVersion,
    pub npm: NpmReport,
    pub cargo: CargoReport,
    pub python: ToolVersion,
    pub uv: ToolVersion,
    pub conda: CondaReport,
    pub go: GoReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolVersion {
    pub path: Option<String>,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NpmReport {
    pub npm: ToolVersion,
    pub prefix: Option<String>,
    pub root: Option<String>,
    pub global_packages: Vec<PackageEntry>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CargoReport {
    pub cargo: ToolVersion,
    pub installed: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CondaReport {
    pub conda: ToolVersion,
    pub platform: Option<String>,
    pub root_prefix: Option<String>,
    pub active_prefix: Option<String>,
    pub envs: Vec<String>,
    pub envs_dirs: Vec<String>,
    pub package_caches: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoReport {
    pub go: ToolVersion,
    pub gopath: Option<String>,
    pub gobin: Option<String>,
    pub goroot: Option<String>,
    pub goos: Option<String>,
    pub goarch: Option<String>,
    pub bin_dir: Option<PathBuf>,
    pub binaries: Vec<GoBinary>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoBinary {
    pub path: PathBuf,
    pub arch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistenceReport {
    pub launch_items: Vec<LaunchItem>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchItem {
    pub path: PathBuf,
    pub label: String,
    pub scope: LaunchItemScope,
    pub program: Option<PathBuf>,
    #[serde(default)]
    pub program_from_arguments: bool,
    #[serde(default)]
    pub program_arguments: Vec<String>,
    #[serde(default)]
    pub translocation_target: Option<String>,
    pub program_exists: Option<bool>,
    pub run_at_load: bool,
    pub keep_alive: bool,
    pub associated_bundle_ids: Vec<String>,
    pub parent_app_present: Option<bool>,
    #[serde(default)]
    pub parent_product: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchItemScope {
    UserAgent,
    SystemAgent,
    SystemDaemon,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeReport {
    pub processes: Vec<ProcessEntry>,
    pub listeners: Vec<ListenerEntry>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    #[serde(default)]
    pub executable: Option<PathBuf>,
    pub elapsed_seconds: u64,
    pub state: String,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerEntry {
    pub pid: u32,
    pub command: Option<String>,
    pub endpoint: String,
    pub port: Option<u16>,
    pub wildcard: bool,
    pub loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorrelationGraph {
    pub nodes: Vec<EvidenceNode>,
    pub edges: Vec<EvidenceEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceNode {
    pub id: String,
    pub kind: EvidenceNodeKind,
    pub label: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceNodeKind {
    LaunchItem,
    Process,
    Listener,
    Executable,
    Application,
    Package,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCategory {
    Architecture,
    PackageManager,
    Environment,
    Persistence,
    Runtime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Risk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub finding_id: String,
    pub decision: DecisionKind,
    pub reason: Option<String>,
    pub created_at_unix: u64,
    pub until_unix: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DecisionKind {
    Keep,
    Ignore,
    Snooze,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub finding: Finding,
    pub decision: DecisionRecord,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionPlan {
    #[serde(default = "action_plan_schema")]
    pub schema_version: u32,
    pub summary: ActionPlanSummary,
    pub actions: Vec<PlannedAction>,
}

fn action_plan_schema() -> u32 {
    2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionPlanSummary {
    pub total: usize,
    pub destructive: usize,
    pub low_risk: usize,
    pub medium_risk: usize,
    pub high_risk: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlannedAction {
    pub id: String,
    pub title: String,
    pub rationale: String,
    pub confidence: Confidence,
    pub risk: ActionRisk,
    pub destructive: bool,
    pub kind: ActionKind,
    #[serde(default)]
    pub controls: ActionControls,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionControls {
    pub requires_root: bool,
    pub source_finding_id: Option<String>,
    pub expected_file: Option<FileIdentity>,
    pub provenance: Vec<String>,
    pub preconditions: Vec<ActionCheck>,
    pub undo: Vec<ActionStep>,
    pub verification: Vec<ActionCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCheck {
    pub description: String,
    #[serde(flatten)]
    pub kind: ActionCheckKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ActionCheckKind {
    PathExists { path: PathBuf },
    PathAbsent { path: PathBuf },
    FindingPresent { finding_id: String },
    FindingAbsent { finding_id: String },
    CommandSucceeds { command: CommandSpec },
    ManualConfirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStep {
    pub description: String,
    pub command: Option<CommandSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub requires_root: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionRisk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ActionKind {
    MoveToTrash { path: PathBuf },
    BrewInstall { package: String },
    Manual { instructions: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDisposition {
    ApplyNow,
    Manual,
    Handoff,
    NeedsMoreEvidence,
}
