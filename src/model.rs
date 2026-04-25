use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct Report {
    pub system: SystemReport,
    pub homebrew: HomebrewReport,
    pub apps: AppsReport,
    pub local_bins: Vec<BinEntry>,
    pub path: PathReport,
    pub dev_tools: DevToolsReport,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct SystemReport {
    pub arch: String,
    pub macos: String,
    pub shell: Option<String>,
}

#[derive(Debug, Serialize, Default)]
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

#[derive(Debug, Serialize, Default)]
pub struct HomebrewService {
    pub name: String,
    pub status: Option<String>,
    pub user: Option<String>,
    pub file: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AppsReport {
    pub scanned_roots: Vec<PathBuf>,
    pub apps: Vec<AppEntry>,
    pub duplicate_bundle_ids: BTreeMap<String, Vec<PathBuf>>,
}

#[derive(Debug, Serialize)]
pub struct AppEntry {
    pub path: PathBuf,
    pub name: Option<String>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub executable: Option<PathBuf>,
    pub executable_arch: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BinEntry {
    pub path: PathBuf,
    pub kind: String,
    pub arch: Option<String>,
    pub target: Option<PathBuf>,
    pub owner: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PathReport {
    pub entries: Vec<String>,
    pub duplicates: BTreeMap<String, usize>,
    pub opt_homebrew_before_usr_local: Option<bool>,
}

#[derive(Debug, Serialize, Default)]
pub struct DevToolsReport {
    pub node: ToolVersion,
    pub npm: NpmReport,
    pub cargo: CargoReport,
    pub python: ToolVersion,
    pub uv: ToolVersion,
    pub conda: CondaReport,
    pub go: GoReport,
}

#[derive(Debug, Serialize, Default)]
pub struct ToolVersion {
    pub path: Option<String>,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct NpmReport {
    pub npm: ToolVersion,
    pub prefix: Option<String>,
    pub root: Option<String>,
    pub global_packages: Vec<PackageEntry>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct CargoReport {
    pub cargo: ToolVersion,
    pub installed: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
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

#[derive(Debug, Serialize, Default)]
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

#[derive(Debug, Serialize)]
pub struct GoBinary {
    pub path: PathBuf,
    pub arch: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Risk,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActionPlan {
    pub summary: ActionPlanSummary,
    pub actions: Vec<PlannedAction>,
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
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
