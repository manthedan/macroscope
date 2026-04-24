use crate::model::*;
use crate::util::*;

pub fn render_markdown(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("# Macroscope Report\n\n");

    out.push_str("## System\n\n");
    out.push_str(&format!("- Architecture: `{}`\n", report.system.arch));
    out.push_str(&format!("- macOS: `{}`\n", report.system.macos));
    if let Some(shell) = &report.system.shell {
        out.push_str(&format!("- Shell: `{shell}`\n"));
    }
    out.push('\n');

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No notable findings.\n\n");
    } else {
        for finding in &report.findings {
            out.push_str(&format!(
                "- **{:?}**: {} — {}\n",
                finding.severity, finding.title, finding.detail
            ));
        }
        out.push('\n');
    }

    out.push_str("## Homebrew\n\n");
    out.push_str(&format!("- brew: `{}`\n", opt(&report.homebrew.brew_path)));
    out.push_str(&format!("- prefix: `{}`\n", opt(&report.homebrew.prefix)));
    out.push_str(&format!("- formulae: {}\n", report.homebrew.formulae.len()));
    out.push_str(&format!("- casks: {}\n", report.homebrew.casks.len()));
    out.push_str(&format!("- leaves: {}\n", report.homebrew.leaves.len()));
    out.push_str(&format!(
        "- outdated formulae: {}\n",
        report.homebrew.outdated_formulae.len()
    ));
    out.push_str(&format!(
        "- outdated casks: {}\n",
        report.homebrew.outdated_casks.len()
    ));
    out.push_str(&format!(
        "- services: {}\n\n",
        report.homebrew.services.len()
    ));

    out.push_str("### Homebrew Outdated Formulae\n\n");
    push_bullets(&mut out, &report.homebrew.outdated_formulae);

    out.push_str("### Homebrew Outdated Casks\n\n");
    push_bullets(&mut out, &report.homebrew.outdated_casks);

    out.push_str("### Homebrew Services\n\n");
    push_homebrew_services_md(&mut out, &report.homebrew.services);

    out.push_str("### Homebrew Autoremove Preview\n\n");
    push_bullets(&mut out, &report.homebrew.autoremove_preview);

    out.push_str("### Homebrew Cleanup Preview\n\n");
    push_bullets(&mut out, &report.homebrew.cleanup_preview);

    out.push_str("### Homebrew Leaves\n\n");
    push_bullets(&mut out, &report.homebrew.leaves);

    out.push_str("## Applications\n\n");
    out.push_str(&format!("Scanned {} apps.\n\n", report.apps.apps.len()));
    push_app_table_md(&mut out, &report.apps.apps);
    if !report.apps.duplicate_bundle_ids.is_empty() {
        out.push_str("### Duplicate Bundle IDs\n\n");
        for (bundle_id, paths) in &report.apps.duplicate_bundle_ids {
            out.push_str(&format!("- `{bundle_id}`\n"));
            for path in paths {
                out.push_str(&format!("  - `{}`\n", path.display()));
            }
        }
        out.push('\n');
    }

    out.push_str("## /usr/local/bin\n\n");
    if report.local_bins.is_empty() {
        out.push_str("No entries found or directory missing.\n\n");
    } else {
        for bin in &report.local_bins {
            out.push_str(&format!("- `{}` — {}", bin.path.display(), bin.kind));
            if let Some(arch) = &bin.arch {
                out.push_str(&format!(", `{arch}`"));
            }
            if let Some(target) = &bin.target {
                out.push_str(&format!(", -> `{}`", target.display()));
            }
            if let Some(owner) = &bin.owner {
                out.push_str(&format!(", owner: `{}`", md_escape(owner)));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str("## Developer Tools\n\n");
    push_tool_md(&mut out, "node", &report.dev_tools.node);
    push_tool_md(&mut out, "npm", &report.dev_tools.npm.npm);
    push_tool_md(&mut out, "python3", &report.dev_tools.python);
    push_tool_md(&mut out, "uv", &report.dev_tools.uv);
    push_tool_md(&mut out, "conda", &report.dev_tools.conda.conda);
    push_tool_md(&mut out, "go", &report.dev_tools.go.go);
    push_tool_md(&mut out, "cargo", &report.dev_tools.cargo.cargo);
    out.push_str(&format!(
        "\n### Global npm Packages ({})\n\n",
        report.dev_tools.npm.global_packages.len()
    ));
    for package in &report.dev_tools.npm.global_packages {
        out.push_str(&format!(
            "- `{}` `{}`\n",
            package.name,
            package.version.as_deref().unwrap_or("unknown")
        ));
    }
    out.push_str(&format!(
        "\n### Cargo-installed Crates ({})\n\n",
        report.dev_tools.cargo.installed.len()
    ));
    push_bullets(&mut out, &report.dev_tools.cargo.installed);

    out.push_str("\n### Conda\n\n");
    push_conda_md(&mut out, &report.dev_tools.conda);

    out.push_str("\n### Go\n\n");
    push_go_md(&mut out, &report.dev_tools.go);

    out.push_str("## PATH\n\n");
    for (idx, entry) in report.path.entries.iter().enumerate() {
        out.push_str(&format!("{}. `{entry}`\n", idx + 1));
    }

    out
}
