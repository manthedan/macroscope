use crate::apply::move_to_trash;
use crate::model::*;
use crate::plan::{
    action_instruction, action_kind_label, generate_action_plan, related_actions_for_finding,
    render_action_plan_markdown,
};
use crate::scan::scan_with_observer;
use crate::util::{opt, tool_line};
use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use owo_colors::OwoColorize;
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

enum TuiOverlay {
    Help,
    Message {
        title: String,
        lines: Vec<String>,
    },
    Confirm {
        target: ConfirmTarget,
        title: String,
        prompt: String,
        required: String,
        buffer: String,
    },
}

#[derive(Debug, Clone, Copy)]
enum ConfirmTarget {
    SelectedAction(usize),
    WholeExecutablePlan,
}

enum ScanEvent {
    Step {
        phase: &'static str,
        index: usize,
        total: usize,
    },
    Done(Report),
}

pub fn run_tui(apply_enabled: bool) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = (|| {
        let report = scan_with_tui_progress(&mut terminal)?;
        let plan = generate_action_plan(&report);
        tui_loop(&mut terminal, report, plan, apply_enabled)
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

pub fn scan_with_tui_progress<B: Backend>(terminal: &mut Terminal<B>) -> Result<Report> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let report = scan_with_observer(|phase, index, total| {
            let _ = tx.send(ScanEvent::Step {
                phase,
                index,
                total,
            });
        });
        let _ = tx.send(ScanEvent::Done(report));
    });

    let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let mut frame_idx = 0;
    let mut phase = "Starting";
    let mut index = 0;
    let mut total = 7;

    loop {
        while let Ok(event) = rx.try_recv() {
            match event {
                ScanEvent::Step {
                    phase: next_phase,
                    index: next_index,
                    total: next_total,
                } => {
                    phase = next_phase;
                    index = next_index;
                    total = next_total;
                }
                ScanEvent::Done(report) => return Ok(report),
            }
        }

        terminal.draw(|frame| {
            let area = centered_rect(62, 38, frame.area());
            frame.render_widget(Clear, area);
            let gauge_width = 28usize;
            let filled = if total == 0 {
                0
            } else {
                gauge_width * index / total
            };
            let bar = format!(
                "{}{}",
                "█".repeat(filled),
                "░".repeat(gauge_width.saturating_sub(filled))
            );
            let paragraph = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(
                        frames[frame_idx % frames.len()],
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        "Scanning your Mac",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(format!("[{index}/{total}] {phase}")),
                Line::from(""),
                Line::from(vec![
                    Span::styled(bar, Style::default().fg(Color::Cyan)),
                    Span::raw(" "),
                    Span::styled("read-only", Style::default().fg(Color::Green)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Homebrew, app, and tool scans can take a moment.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(Block::default().title("Macroscope").borders(Borders::ALL))
            .wrap(Wrap { trim: true });
            frame.render_widget(paragraph, area);
        })?;

        frame_idx += 1;
        thread::sleep(Duration::from_millis(90));
    }
}

pub fn tui_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    mut report: Report,
    mut plan: ActionPlan,
    apply_enabled: bool,
) -> Result<()> {
    let mut active_tab = TuiTab::Findings;
    let mut selected_finding = if report.findings.is_empty() {
        None
    } else {
        Some(0)
    };
    let mut selected_action = if plan.actions.is_empty() {
        None
    } else {
        Some(0)
    };
    let mut overlay: Option<TuiOverlay> = None;
    let mut dry_run_actions = BTreeSet::new();
    let mut plan_dry_run_done = false;
    let mut status = if apply_enabled {
        "Apply mode enabled. Move-to-Trash actions still require dry-run and typed confirmation."
            .to_string()
    } else {
        "Read-only TUI. Restart with `macroscope tui --apply` to enable guarded apply controls."
            .to_string()
    };

    loop {
        terminal.draw(|frame| {
            let root = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(11),
                    Constraint::Min(8),
                    Constraint::Length(4),
                ])
                .split(frame.area());

            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    "◉ ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Macroscope",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                tab_span("Findings", active_tab == TuiTab::Findings),
                Span::raw("  "),
                tab_span("Plan", active_tab == TuiTab::Plan),
                Span::raw("  "),
                Span::styled(
                    if apply_enabled {
                        "apply-capable audit"
                    } else {
                        "read-only audit"
                    },
                    Style::default().fg(if apply_enabled {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }),
                ),
            ]))
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(title, root[0]);

            let overview_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(root[1]);

            let intel_bins = intel_bin_count(&report);
            let intel_apps = intel_app_count(&report);
            let (risks, warns, infos) = finding_counts(&report);

            let overview = Paragraph::new(vec![
                Line::from(vec![Span::styled(
                    format!("macOS {} ({})", report.system.macos, report.system.arch),
                    Style::default().add_modifier(Modifier::BOLD),
                )]),
                Line::from(format!("Homebrew: {}", opt(&report.homebrew.prefix))),
                Line::from(format!(
                    "Packages: {} formulae · {} casks · {} leaves",
                    report.homebrew.formulae.len(),
                    report.homebrew.casks.len(),
                    report.homebrew.leaves.len()
                )),
                Line::from(format!(
                    "Homebrew: {} outdated · {} services",
                    report.homebrew.outdated_formulae.len() + report.homebrew.outdated_casks.len(),
                    report.homebrew.services.len()
                )),
                Line::from(format!(
                    "Apps: {} scanned · {} Intel-only · {} duplicate IDs",
                    report.apps.apps.len(),
                    intel_apps,
                    report.apps.duplicate_bundle_ids.len()
                )),
                Line::from(format!(
                    "/usr/local/bin: {} entries · {} Intel-only",
                    report.local_bins.len(),
                    intel_bins
                )),
                Line::from(format!(
                    "Plan: {} actions · {} executable · {} destructive",
                    plan.summary.total,
                    executable_action_count(&plan),
                    plan.summary.destructive
                )),
            ])
            .block(Block::default().title("Overview").borders(Borders::ALL));
            frame.render_widget(overview, overview_chunks[0]);

            let tools = Paragraph::new(vec![
                Line::from(format!("node: {}", tool_line(&report.dev_tools.node))),
                Line::from(format!("npm: {}", tool_line(&report.dev_tools.npm.npm))),
                Line::from(format!(
                    "npm globals: {}",
                    report.dev_tools.npm.global_packages.len()
                )),
                Line::from(format!(
                    "cargo installs: {}",
                    report.dev_tools.cargo.installed.len()
                )),
                Line::from(format!("python3: {}", tool_line(&report.dev_tools.python))),
                Line::from(format!(
                    "conda: {} envs · {}",
                    report.dev_tools.conda.envs.len(),
                    report
                        .dev_tools
                        .conda
                        .platform
                        .as_deref()
                        .unwrap_or("unknown")
                )),
                Line::from(format!(
                    "go: {} GOPATH/bin binaries",
                    report.dev_tools.go.binaries.len()
                )),
            ])
            .block(
                Block::default()
                    .title("Developer tools")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });
            frame.render_widget(tools, overview_chunks[1]);

            let body_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(root[2]);

            match active_tab {
                TuiTab::Findings => render_findings_tab(
                    frame,
                    body_chunks[0],
                    body_chunks[1],
                    &report,
                    &plan,
                    selected_finding,
                    risks,
                    warns,
                    infos,
                ),
                TuiTab::Plan => render_plan_tab(
                    frame,
                    body_chunks[0],
                    body_chunks[1],
                    &plan,
                    selected_action,
                ),
            }

            let mode = if apply_enabled {
                Span::styled(
                    "APPLY MODE",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    "READ ONLY",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            };
            let footer = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("Tab", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" switch · "),
                    Span::styled("j/k", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" move · "),
                    Span::styled("e", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" explain · "),
                    Span::styled("d/D", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" dry-run · "),
                    Span::styled("x/m", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" export · "),
                    Span::styled("a/A", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" apply · "),
                    Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" rescan · "),
                    Span::styled("?", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" help · "),
                    Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" quit"),
                ]),
                Line::from(vec![mode, Span::raw(format!("  {status}"))]),
            ])
            .block(Block::default().borders(Borders::ALL));
            frame.render_widget(footer, root[3]);

            if let Some(overlay) = &overlay {
                render_tui_overlay(frame, overlay);
            }
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if let Some(current_overlay) = overlay.as_mut() {
                    match current_overlay {
                        TuiOverlay::Help | TuiOverlay::Message { .. } => match key.code {
                            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter => overlay = None,
                            _ => {}
                        },
                        TuiOverlay::Confirm {
                            target,
                            required,
                            buffer,
                            ..
                        } => match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                status = "Apply confirmation cancelled.".into();
                                overlay = None;
                            }
                            KeyCode::Backspace => {
                                buffer.pop();
                            }
                            KeyCode::Enter => {
                                if buffer == required {
                                    let lines = match *target {
                                        ConfirmTarget::SelectedAction(idx) => plan
                                            .actions
                                            .get(idx)
                                            .map(apply_tui_action)
                                            .unwrap_or_else(|| {
                                                vec!["Selected action no longer exists.".into()]
                                            }),
                                        ConfirmTarget::WholeExecutablePlan => {
                                            apply_tui_executable_plan(&plan)
                                        }
                                    };
                                    status = "Apply command finished; review result modal.".into();
                                    overlay = Some(TuiOverlay::Message {
                                        title: "Apply result".into(),
                                        lines,
                                    });
                                } else {
                                    status = format!(
                                        "Confirmation did not match. Type exactly `{required}` or Esc to cancel."
                                    );
                                    buffer.clear();
                                }
                            }
                            KeyCode::Char(ch) => buffer.push(ch),
                            _ => {}
                        },
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => active_tab = toggle_tab(active_tab),
                    KeyCode::Char('f') => active_tab = TuiTab::Findings,
                    KeyCode::Char('p') => active_tab = TuiTab::Plan,
                    KeyCode::Down | KeyCode::Char('j') => match active_tab {
                        TuiTab::Findings => {
                            selected_finding = next_finding(selected_finding, report.findings.len())
                        }
                        TuiTab::Plan => {
                            selected_action = next_finding(selected_action, plan.actions.len())
                        }
                    },
                    KeyCode::Up | KeyCode::Char('k') => match active_tab {
                        TuiTab::Findings => {
                            selected_finding =
                                previous_finding(selected_finding, report.findings.len())
                        }
                        TuiTab::Plan => {
                            selected_action = previous_finding(selected_action, plan.actions.len())
                        }
                    },
                    KeyCode::Char('?') => overlay = Some(TuiOverlay::Help),
                    KeyCode::Char('e') => {
                        overlay = Some(TuiOverlay::Message {
                            title: "Explain".into(),
                            lines: tui_explain_lines(
                                active_tab,
                                selected_finding,
                                selected_action,
                                &report,
                                &plan,
                            ),
                        });
                    }
                    KeyCode::Char('d') => match active_tab {
                        TuiTab::Findings => {
                            let Some(finding) =
                                selected_finding.and_then(|idx| report.findings.get(idx))
                            else {
                                status = "No finding selected to dry-run.".into();
                                continue;
                            };
                            let related = related_actions_for_finding(finding, &plan);
                            if related.is_empty() {
                                status = "Selected finding has no related plan actions to dry-run."
                                    .into();
                                continue;
                            }
                            for action in &related {
                                dry_run_actions.insert(action.id.clone());
                            }
                            let count = related.len();
                            overlay = Some(TuiOverlay::Message {
                                title: "Related action dry run".into(),
                                lines: dry_run_related_actions_lines(finding, &related),
                            });
                            status = format!(
                                "Dry-run recorded for {count} action(s) related to the selected finding."
                            );
                        }
                        TuiTab::Plan => {
                            if let Some(action) =
                                selected_action.and_then(|idx| plan.actions.get(idx))
                            {
                                dry_run_actions.insert(action.id.clone());
                                overlay = Some(TuiOverlay::Message {
                                    title: "Selected action dry run".into(),
                                    lines: dry_run_action_lines(action),
                                });
                                status = format!("Dry-run recorded for `{}`.", action.id);
                            } else {
                                status = "No plan action selected to dry-run.".into();
                            }
                        }
                    },
                    KeyCode::Char('D') => {
                        plan_dry_run_done = true;
                        overlay = Some(TuiOverlay::Message {
                            title: "Whole-plan dry run".into(),
                            lines: dry_run_plan_lines(&plan),
                        });
                        status = "Whole-plan dry-run recorded for this TUI session.".into();
                    }
                    KeyCode::Char('x') => match export_plan_json(&plan) {
                        Ok(path) => status = format!("Exported JSON plan to {}", path.display()),
                        Err(err) => status = format!("Failed to export JSON plan: {err}"),
                    },
                    KeyCode::Char('m') => match export_plan_markdown(&plan) {
                        Ok(path) => {
                            status = format!("Exported Markdown plan to {}", path.display())
                        }
                        Err(err) => status = format!("Failed to export Markdown plan: {err}"),
                    },
                    KeyCode::Char('r') => {
                        report = scan_with_tui_progress(terminal)?;
                        plan = generate_action_plan(&report);
                        selected_finding = if report.findings.is_empty() {
                            None
                        } else {
                            Some(0)
                        };
                        selected_action = if plan.actions.is_empty() {
                            None
                        } else {
                            Some(0)
                        };
                        dry_run_actions.clear();
                        plan_dry_run_done = false;
                        status = "Rescanned and regenerated the action plan.".into();
                    }
                    KeyCode::Char('a') => {
                        if !apply_enabled {
                            status = "Apply is disabled in read-only TUI mode. Restart with `macroscope tui --apply`.".into();
                            continue;
                        }
                        let Some(idx) = selected_action else {
                            status = "No selected plan action to apply.".into();
                            continue;
                        };
                        let Some(action) = plan.actions.get(idx) else {
                            status = "Selected plan action no longer exists.".into();
                            continue;
                        };
                        if !is_executable_action(action) {
                            overlay = Some(TuiOverlay::Message {
                                title: "Review-only action".into(),
                                lines: vec![
                                    format!("`{}` is not executable by Macroscope yet.", action.id),
                                    format!("Kind: {}", action_kind_label(&action.kind)),
                                    "".into(),
                                    format!(
                                        "Suggested instruction: {}",
                                        action_instruction(action)
                                    ),
                                ],
                            });
                            status = "Review-only action was not executed.".into();
                            continue;
                        }
                        if !dry_run_actions.contains(&action.id) {
                            dry_run_actions.insert(action.id.clone());
                            overlay = Some(TuiOverlay::Message {
                                title: "Dry-run required first".into(),
                                lines: dry_run_action_lines(action),
                            });
                            status =
                                "Dry-run recorded. Press `a` again to request confirmation.".into();
                            continue;
                        }
                        overlay = Some(confirm_selected_action_overlay(idx, action));
                    }
                    KeyCode::Char('A') => {
                        if !apply_enabled {
                            status = "Apply is disabled in read-only TUI mode. Restart with `macroscope tui --apply`.".into();
                            continue;
                        }
                        let count = executable_action_count(&plan);
                        if count == 0 {
                            status =
                                "No executable Move-to-Trash actions in the current plan.".into();
                            continue;
                        }
                        if !plan_dry_run_done {
                            plan_dry_run_done = true;
                            overlay = Some(TuiOverlay::Message {
                                title: "Whole-plan dry run required first".into(),
                                lines: dry_run_plan_lines(&plan),
                            });
                            status = "Whole-plan dry-run recorded. Press `A` again to request confirmation.".into();
                            continue;
                        }
                        overlay = Some(confirm_whole_plan_overlay(count));
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn render_tui_overlay(frame: &mut ratatui::Frame<'_>, overlay: &TuiOverlay) {
    let area = centered_rect(74, 72, frame.area());
    frame.render_widget(Clear, area);

    let (title, lines) = match overlay {
        TuiOverlay::Help => (
            "TUI help".to_string(),
            vec![
                "Tab / f / p: switch between Findings and Plan".into(),
                "j/k or arrows: move selection".into(),
                "e: explain selected finding or action".into(),
                "d: dry-run selected plan action, or related actions for a selected finding".into(),
                "D: dry-run the whole generated plan".into(),
                "x: export plan JSON to ./macroscope-plan.json".into(),
                "m: export plan Markdown to ./macroscope-plan.md".into(),
                "r: rescan and regenerate plan".into(),
                "a: apply selected executable action; requires --apply, dry-run, and typed confirmation".into(),
                "A: apply all executable actions; requires --apply, dry-run, and typed confirmation".into(),
                "q / Esc: close modal or quit".into(),
            ],
        ),
        TuiOverlay::Message { title, lines } => (title.clone(), lines.clone()),
        TuiOverlay::Confirm {
            title,
            prompt,
            required,
            buffer,
            ..
        } => (
            title.clone(),
            vec![
                prompt.clone(),
                "".into(),
                format!("Type exactly `{required}` and press Enter."),
                "Esc cancels.".into(),
                "".into(),
                format!("Confirmation: {buffer}"),
            ],
        ),
    };

    let paragraph = Paragraph::new(
        lines
            .into_iter()
            .map(Line::from)
            .collect::<Vec<Line<'static>>>(),
    )
    .block(Block::default().title(title).borders(Borders::ALL))
    .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

pub fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

pub fn tui_explain_lines(
    active_tab: TuiTab,
    selected_finding: Option<usize>,
    selected_action: Option<usize>,
    report: &Report,
    plan: &ActionPlan,
) -> Vec<String> {
    match active_tab {
        TuiTab::Findings => selected_finding
            .and_then(|idx| report.findings.get(idx))
            .map(|finding| {
                let mut lines = vec![
                    format!("{} — {}", severity_label(&finding.severity), finding.title),
                    "".into(),
                    finding.detail.clone(),
                ];
                let related = related_actions_for_finding(finding, plan);
                if !related.is_empty() {
                    lines.push("".into());
                    lines.push("Related actions:".into());
                    for action in related {
                        lines.push(format!("- {} ({})", action.title, action.id));
                    }
                }
                lines
            })
            .unwrap_or_else(|| vec!["No finding selected.".into()]),
        TuiTab::Plan => selected_action
            .and_then(|idx| plan.actions.get(idx))
            .map(action_explain_lines)
            .unwrap_or_else(|| vec!["No action selected.".into()]),
    }
}

pub fn action_explain_lines(action: &PlannedAction) -> Vec<String> {
    vec![
        action.title.clone(),
        "".into(),
        format!("ID: {}", action.id),
        format!("Kind: {}", action_kind_label(&action.kind)),
        format!("Risk: {:?}", action.risk),
        format!("Confidence: {:?}", action.confidence),
        format!("Destructive: {}", action.destructive),
        "".into(),
        action.rationale.clone(),
        "".into(),
        format!("Suggested instruction: {}", action_instruction(action)),
    ]
}

pub fn dry_run_action_lines(action: &PlannedAction) -> Vec<String> {
    let mut lines = vec![
        format!("Would evaluate action `{}`.", action.id),
        format!("Title: {}", action.title),
        format!("Risk: {:?}", action.risk),
        format!("Confidence: {:?}", action.confidence),
        format!("Destructive: {}", action.destructive),
        "".into(),
    ];
    match &action.kind {
        ActionKind::MoveToTrash { path } => {
            lines.push(format!("Would move to Trash: {}", path.display()));
            lines.push("Real apply requires `macroscope tui --apply`, this dry-run, then typed TRASH confirmation.".into());
        }
        ActionKind::BrewInstall { package } => {
            lines.push(format!(
                "Would suggest, but not execute: brew install {package}"
            ));
            lines.push("Package-manager actions are review-only in the TUI for now.".into());
        }
        ActionKind::Manual { instructions } => {
            lines.push(format!("Manual instruction: {instructions}"));
            lines.push("Manual actions are never auto-executed.".into());
        }
    }
    lines
}

pub fn dry_run_related_actions_lines(finding: &Finding, actions: &[&PlannedAction]) -> Vec<String> {
    let mut lines = vec![
        format!("Finding: {}", finding.title),
        finding.detail.clone(),
        "".into(),
        format!("Related actions to dry-run: {}", actions.len()),
        "".into(),
    ];

    for action in actions {
        let prefix = if is_executable_action(action) {
            "Would run"
        } else {
            "Would skip/review"
        };
        lines.push(format!("{prefix}: {} ({})", action.title, action.id));
        lines.push(format!("  {}", action_instruction(action)));
    }

    lines
}

pub fn dry_run_plan_lines(plan: &ActionPlan) -> Vec<String> {
    let mut lines = vec![
        format!("Plan actions: {}", plan.summary.total),
        format!(
            "Executable Move-to-Trash actions: {}",
            executable_action_count(plan)
        ),
        format!("Destructive actions: {}", plan.summary.destructive),
        "".into(),
    ];

    for action in &plan.actions {
        let prefix = if is_executable_action(action) {
            "Would run"
        } else {
            "Would skip/review"
        };
        lines.push(format!("{prefix}: {} ({})", action.title, action.id));
    }

    if plan.actions.is_empty() {
        lines.push("No actions proposed.".into());
    }
    lines
}

pub fn export_plan_json(plan: &ActionPlan) -> Result<PathBuf> {
    let path = PathBuf::from("macroscope-plan.json");
    fs::write(&path, serde_json::to_string_pretty(plan)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn export_plan_markdown(plan: &ActionPlan) -> Result<PathBuf> {
    let path = PathBuf::from("macroscope-plan.md");
    fs::write(&path, render_action_plan_markdown(plan))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn is_executable_action(action: &PlannedAction) -> bool {
    matches!(action.kind, ActionKind::MoveToTrash { .. })
}

pub fn executable_action_count(plan: &ActionPlan) -> usize {
    plan.actions
        .iter()
        .filter(|action| is_executable_action(action))
        .count()
}

fn confirm_selected_action_overlay(idx: usize, action: &PlannedAction) -> TuiOverlay {
    let path = match &action.kind {
        ActionKind::MoveToTrash { path } => path.display().to_string(),
        _ => "non-executable action".into(),
    };
    TuiOverlay::Confirm {
        target: ConfirmTarget::SelectedAction(idx),
        title: "Confirm selected apply".into(),
        prompt: format!(
            "Move this path to Trash?\n\n{path}\n\nAction: {}\nRisk: {:?}",
            action.id, action.risk
        ),
        required: "TRASH".into(),
        buffer: String::new(),
    }
}

fn confirm_whole_plan_overlay(count: usize) -> TuiOverlay {
    TuiOverlay::Confirm {
        target: ConfirmTarget::WholeExecutablePlan,
        title: "Confirm plan apply".into(),
        prompt: format!(
            "Move {count} executable plan item(s) to Trash? Review-only actions will be skipped."
        ),
        required: format!("APPLY {count}"),
        buffer: String::new(),
    }
}

pub fn apply_tui_action(action: &PlannedAction) -> Vec<String> {
    match &action.kind {
        ActionKind::MoveToTrash { path } => match move_to_trash(path) {
            Ok(()) => vec![
                format!("Applied: {}", action.title),
                format!("Moved to Trash: {}", path.display()),
            ],
            Err(err) => vec![format!("Failed: {}", action.title), format!("Error: {err}")],
        },
        ActionKind::BrewInstall { .. } | ActionKind::Manual { .. } => vec![
            format!("Skipped review-only action: {}", action.title),
            format!("Instruction: {}", action_instruction(action)),
        ],
    }
}

pub fn apply_tui_executable_plan(plan: &ActionPlan) -> Vec<String> {
    let mut lines = Vec::new();
    for action in &plan.actions {
        if is_executable_action(action) {
            lines.extend(apply_tui_action(action));
            lines.push("".into());
        }
    }
    if lines.is_empty() {
        lines.push("No executable actions were applied.".into());
    }
    lines
}

pub fn render_findings_tab(
    frame: &mut ratatui::Frame<'_>,
    list_area: ratatui::layout::Rect,
    detail_area: ratatui::layout::Rect,
    report: &Report,
    plan: &ActionPlan,
    selected: Option<usize>,
    risks: usize,
    warns: usize,
    infos: usize,
) {
    let items: Vec<ListItem> = if report.findings.is_empty() {
        vec![ListItem::new(Line::from(vec![Span::styled(
            "No notable findings. Nice.",
            Style::default().fg(Color::Green),
        )]))]
    } else {
        report
            .findings
            .iter()
            .map(|finding| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:<4} ", severity_label(&finding.severity)),
                        tui_severity_style(&finding.severity),
                    ),
                    Span::raw(finding.title.clone()),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    state.select(selected);
    let findings = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "Findings  {risks} risk · {warns} warn · {infos} info"
                ))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➜ ");
    frame.render_stateful_widget(findings, list_area, &mut state);

    let detail_lines =
        if let Some(idx) = selected.and_then(|idx| report.findings.get(idx).map(|_| idx)) {
            let finding = &report.findings[idx];
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(
                        severity_label(&finding.severity),
                        tui_severity_style(&finding.severity),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        finding.title.clone(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(finding.detail.clone()),
                Line::from(""),
            ];

            let related = related_actions_for_finding(finding, plan);
            if !related.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Related actions:",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                for action in related.into_iter().take(3) {
                    lines.push(Line::from(format!("- {}", action.title)));
                }
                lines.push(Line::from(""));
            }

            lines.push(Line::from(Span::styled(
                format!("Finding {} of {}", idx + 1, report.findings.len()),
                Style::default().fg(Color::DarkGray),
            )));
            lines
        } else {
            vec![Line::from("No finding selected.")]
        };

    let detail = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title("Finding detail")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, detail_area);
}

pub fn render_plan_tab(
    frame: &mut ratatui::Frame<'_>,
    list_area: ratatui::layout::Rect,
    detail_area: ratatui::layout::Rect,
    plan: &ActionPlan,
    selected: Option<usize>,
) {
    let items: Vec<ListItem> = if plan.actions.is_empty() {
        vec![ListItem::new(Line::from(vec![Span::styled(
            "No actions proposed. Nice.",
            Style::default().fg(Color::Green),
        )]))]
    } else {
        plan.actions
            .iter()
            .map(|action| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:<4} ", risk_label(action.risk)),
                        tui_risk_style(action.risk),
                    ),
                    Span::raw(action.title.clone()),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    state.select(selected);
    let actions = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "Plan  {} actions · {} destructive",
                    plan.summary.total, plan.summary.destructive
                ))
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("➜ ");
    frame.render_stateful_widget(actions, list_area, &mut state);

    let detail_lines =
        if let Some(idx) = selected.and_then(|idx| plan.actions.get(idx).map(|_| idx)) {
            let action = &plan.actions[idx];
            vec![
                Line::from(vec![
                    Span::styled(risk_label(action.risk), tui_risk_style(action.risk)),
                    Span::raw("  "),
                    Span::styled(
                        confidence_label(action.confidence),
                        Style::default().fg(Color::Blue),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    action.title.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!("ID: {}", action.id)),
                Line::from(format!("Kind: {}", action_kind_label(&action.kind))),
                Line::from(format!("Destructive: {}", action.destructive)),
                Line::from(""),
                Line::from(action.rationale.clone()),
                Line::from(""),
                Line::from(format!("Action: {}", action_instruction(action))),
                Line::from(""),
                Line::from(Span::styled(
                    format!("Action {} of {}", idx + 1, plan.actions.len()),
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        } else {
            vec![Line::from("No action selected.")]
        };

    let detail = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title("Action detail")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, detail_area);
}

pub fn tab_span(label: &'static str, active: bool) -> Span<'static> {
    if active {
        Span::styled(
            format!("[{label}]"),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(format!(" {label} "), Style::default().fg(Color::DarkGray))
    }
}

pub fn toggle_tab(tab: TuiTab) -> TuiTab {
    match tab {
        TuiTab::Findings => TuiTab::Plan,
        TuiTab::Plan => TuiTab::Findings,
    }
}

pub fn risk_label(risk: ActionRisk) -> &'static str {
    match risk {
        ActionRisk::Low => "LOW",
        ActionRisk::Medium => "MED",
        ActionRisk::High => "HIGH",
    }
}

pub fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low-confidence",
        Confidence::Medium => "medium-confidence",
        Confidence::High => "high-confidence",
    }
}

pub fn tui_risk_style(risk: ActionRisk) -> Style {
    match risk {
        ActionRisk::Low => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        ActionRisk::Medium => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        ActionRisk::High => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

pub fn next_finding(selected: Option<usize>, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(selected.map_or(0, |idx| (idx + 1).min(len - 1)))
    }
}

pub fn previous_finding(selected: Option<usize>, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(selected.map_or(0, |idx| idx.saturating_sub(1)))
    }
}

pub fn intel_bin_count(report: &Report) -> usize {
    report
        .local_bins
        .iter()
        .filter(|bin| {
            bin.arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
        })
        .count()
}

pub fn intel_app_count(report: &Report) -> usize {
    report
        .apps
        .apps
        .iter()
        .filter(|app| {
            app.executable_arch
                .as_deref()
                .is_some_and(|arch| arch.contains("x86_64") && !arch.contains("arm64"))
        })
        .count()
}

pub fn finding_counts(report: &Report) -> (usize, usize, usize) {
    let mut risks = 0;
    let mut warns = 0;
    let mut infos = 0;

    for finding in &report.findings {
        match finding.severity {
            Severity::Risk => risks += 1,
            Severity::Warn => warns += 1,
            Severity::Info => infos += 1,
        }
    }

    (risks, warns, infos)
}

pub fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Risk => "RISK",
        Severity::Warn => "WARN",
        Severity::Info => "INFO",
    }
}

pub fn severity_badge(severity: &Severity) -> String {
    match severity {
        Severity::Risk => "RISK".red().bold().to_string(),
        Severity::Warn => "WARN".yellow().bold().to_string(),
        Severity::Info => "INFO".blue().bold().to_string(),
    }
}

pub fn tui_severity_style(severity: &Severity) -> Style {
    match severity {
        Severity::Risk => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::Warn => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        Severity::Info => Style::default()
            .fg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    }
}
