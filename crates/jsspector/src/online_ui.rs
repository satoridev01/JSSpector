//! Interactive terminal view for `jsspector online`.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, Paragraph, Row, Table, Wrap};
use serde::Deserialize;

const EVENT_PREFIX: &str = "@@JSSPECTOR_ONLINE@@";
const MAX_ACTIVITY: usize = 10;
/// The controller reads this file in the run directory to change the Docker slots of a live pass.
const CONTROL_FILE: &str = "control.json";
const MAX_DOCKER_SLOTS: u64 = 64;
const HELP: &[&str] = &[
    "Keys",
    "  + / -     raise or lower the Docker verification slots (pauses the governor;",
    "            its memory guard may still lower them)",
    "  a         hand the slots back to the governor",
    "  h / ?     show or hide this help        q / Esc   stop safely (work stays resumable)",
    "",
    "Verification   docker active/limit (+queued) · whole-host CPU and memory",
    "Where to improve",
    "  Docker time  how slot time ends: issue, no repro, skipped (never driven), timeout,",
    "               error; build/start vs probing; Docker minutes per verified issue",
    "  Bottleneck   verification = slots full with work queued → more slots help;",
    "               static = cloning can't keep up (network); checkouts; discovery = GitHub",
    "  Lanes        issues and Docker minutes per issue for each lane",
];
/// The issue rate is shown only after this long: one early finding would otherwise read as an
/// absurd hourly average.
const RATE_WARMUP: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Deserialize)]
struct WireEvent {
    #[serde(rename = "type")]
    kind: String,
    repository: Option<String>,
    run_id: Option<String>,
    output: Option<String>,
    lane: Option<String>,
    outcome: Option<String>,
    total: Option<u64>,
    found: Option<u64>,
    findings: Option<u64>,
    fix_attempted: Option<bool>,
    fix_proven: Option<bool>,
    success: Option<bool>,
    message: Option<String>,
    cpu: Option<f64>,
    memory: Option<f64>,
    active: Option<u64>,
    waiting: Option<u64>,
    slots: Option<u64>,
    report: Option<String>,
    lines: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
enum KeyAction {
    Stop,
    Handled,
}

enum ControllerLine {
    Output(String),
    Error(String),
}

#[derive(Default)]
struct State {
    phase: String,
    run_id: String,
    output: String,
    total: u64,
    discovered: u64,
    static_done: u64,
    static_failed: u64,
    deterministic_queued: u64,
    deterministic_running: u64,
    deterministic_done: u64,
    ai_queued: u64,
    ai_running: u64,
    ai_done: u64,
    verified_repositories: u64,
    verified_findings: u64,
    fixes_attempted: u64,
    fixes_proven: u64,
    synced: u64,
    failures: u64,
    timeouts: u64,
    last_repository: String,
    discovery_active: bool,
    stopping: bool,
    finished: bool,
    activity: VecDeque<String>,
    /// Whole-host CPU and memory use and the live Docker slot limit, from `resources` events.
    cpu: Option<f64>,
    memory: Option<f64>,
    docker_active: u64,
    docker_waiting: u64,
    docker_slots: u64,
    /// The calibration report, printed after the dashboard closes.
    report: Option<String>,
    /// Improvement metrics from the controller: where Docker time goes, the limiting stage and
    /// each lane's yield.
    performance: Vec<String>,
    /// Docker slots the operator asked for that the controller has not confirmed yet.
    requested_slots: Option<u64>,
    show_help: bool,
}

impl State {
    fn new() -> Self {
        Self {
            phase: "Starting".to_owned(),
            ..Self::default()
        }
    }

    fn activity(&mut self, value: impl Into<String>) {
        let value = value.into();
        if value.trim().is_empty() {
            return;
        }
        self.activity.push_back(value);
        while self.activity.len() > MAX_ACTIVITY {
            self.activity.pop_front();
        }
    }

    fn apply(&mut self, event: WireEvent) {
        if let Some(repository) = event.repository.as_ref() {
            self.last_repository.clone_from(repository);
        }
        match event.kind.as_str() {
            "run_started" => {
                self.phase = "Starting".to_owned();
                self.run_id = event.run_id.unwrap_or_default();
                self.output = event.output.unwrap_or_default();
                self.total = event.total.unwrap_or_default();
                if self.total > 0 {
                    self.activity(format!("inventory ready: {} repositories", self.total));
                } else {
                    self.activity("run initialized; inventory is still being discovered");
                }
            }
            "discovery_started" => {
                self.discovery_active = true;
                self.phase = "Discovery + analysis".to_owned();
                self.activity("querying GitHub's bounded 24-hour inventory");
            }
            "discovery_completed" => {
                self.discovery_active = false;
                self.discovered = event.found.unwrap_or_default();
                self.total = event.total.unwrap_or(self.discovered);
                self.phase = if self.deterministic_running + self.ai_running > 0 {
                    "Dynamic verification".to_owned()
                } else {
                    "Static analysis".to_owned()
                };
                self.activity(format!("discovered {} repositories", self.discovered));
            }
            "discovery_progress" => {
                self.discovered = event.found.unwrap_or(self.discovered);
            }
            "discovery_status" => {}
            "static_finished" => {
                self.static_done += 1;
                if self.discovery_active {
                    self.phase = if self.deterministic_running + self.ai_running > 0 {
                        "Discovery + verification".to_owned()
                    } else {
                        "Discovery + analysis".to_owned()
                    };
                }
                if event
                    .outcome
                    .as_deref()
                    .is_some_and(|value| value == "failed")
                {
                    self.static_failed += 1;
                    self.failures += 1;
                    if event
                        .message
                        .as_deref()
                        .is_some_and(|value| value.contains("timeout"))
                    {
                        self.timeouts += 1;
                    }
                }
            }
            "verification_queued" => match event.lane.as_deref() {
                Some("ai") => self.ai_queued += 1,
                _ => self.deterministic_queued += 1,
            },
            "verification_started" => {
                self.phase = if self.discovery_active {
                    "Discovery + verification".to_owned()
                } else {
                    "Dynamic verification".to_owned()
                };
                match event.lane.as_deref() {
                    Some("ai") => {
                        self.ai_queued = self.ai_queued.saturating_sub(1);
                        self.ai_running += 1;
                    }
                    _ => {
                        self.deterministic_queued = self.deterministic_queued.saturating_sub(1);
                        self.deterministic_running += 1;
                    }
                }
                if let Some(repository) = event.repository {
                    self.activity(format!("verifying {repository}"));
                }
            }
            "verification_finished" => {
                match event.lane.as_deref() {
                    Some("ai") => {
                        self.ai_running = self.ai_running.saturating_sub(1);
                        self.ai_done += 1;
                    }
                    _ => {
                        self.deterministic_running = self.deterministic_running.saturating_sub(1);
                        self.deterministic_done += 1;
                    }
                }
                let findings = event.findings.unwrap_or_default();
                if findings > 0 {
                    self.verified_repositories += 1;
                    self.verified_findings += findings;
                }
                if event.fix_attempted.unwrap_or(false) {
                    self.fixes_attempted += 1;
                }
                if event.fix_proven.unwrap_or(false) {
                    self.fixes_proven += 1;
                }
                if event
                    .outcome
                    .as_deref()
                    .is_some_and(|value| value == "failed")
                {
                    self.failures += 1;
                    if event
                        .message
                        .as_deref()
                        .is_some_and(|value| value.contains("timeout"))
                    {
                        self.timeouts += 1;
                    }
                }
            }
            "sync_finished" => {
                if event.success.unwrap_or(false) {
                    self.synced += event.findings.unwrap_or(1);
                } else {
                    self.failures += 1;
                }
            }
            "operational_failure" => {
                self.failures += 1;
            }
            "run_finished" => {
                self.phase = "Finished".to_owned();
                self.finished = true;
                self.activity("run completed; durable artifacts are ready");
            }
            "run_stopping" => {
                self.phase = "Stopping".to_owned();
                self.stopping = true;
                self.activity("stopping safely; waiting for owned work to exit");
            }
            "run_interrupted" => {
                self.phase = "Interrupted".to_owned();
                self.finished = true;
                self.activity("run stopped; completed work remains resumable");
            }
            "resources" => {
                if event.cpu.is_some() {
                    self.cpu = event.cpu;
                }
                if event.memory.is_some() {
                    self.memory = event.memory;
                }
                if let Some(active) = event.active {
                    self.docker_active = active;
                }
                if let Some(slots) = event.slots {
                    self.docker_slots = slots;
                    if self.requested_slots == Some(slots) {
                        self.requested_slots = None;
                    }
                }
                if let Some(waiting) = event.waiting {
                    self.docker_waiting = waiting;
                }
            }
            "performance" => {
                if let Some(lines) = event.lines {
                    self.performance = lines;
                }
            }
            "calibration_finished" => {
                self.phase = if event.success == Some(true) {
                    "Calibrated".to_owned()
                } else {
                    "Calibration incomplete".to_owned()
                };
                self.finished = true;
                self.report = event.report;
            }
            _ => {}
        }
        if let Some(message) = event.message {
            self.activity(message);
        }
    }

    /// Average verified findings (the issues this pass yields) per hour since it started, once
    /// the warm-up has passed.
    fn issues_per_hour(&self, elapsed: Duration) -> Option<f64> {
        (elapsed >= RATE_WARMUP)
            .then(|| self.verified_findings as f64 * 3600.0 / elapsed.as_secs_f64())
    }

    fn issue_rate(&self, elapsed: Duration) -> String {
        self.issues_per_hour(elapsed)
            .map_or_else(|| "–".to_owned(), |rate| format!("{rate:.1}"))
    }

    /// Everything but a stop is handled here: the slot shortcuts and the help overlay.
    fn on_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> KeyAction {
        match code {
            KeyCode::Esc if self.show_help => self.show_help = false,
            KeyCode::Char('q') | KeyCode::Esc => return KeyAction::Stop,
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return KeyAction::Stop;
            }
            KeyCode::Char('+' | '=') => self.adjust_slots(1),
            KeyCode::Char('-' | '_') => self.adjust_slots(-1),
            KeyCode::Char('a') => self.resume_governor(),
            KeyCode::Char('h' | 'H' | '?') => self.show_help = !self.show_help,
            _ => {}
        }
        KeyAction::Handled
    }

    fn control_path(&self) -> Option<std::path::PathBuf> {
        (!self.output.is_empty()).then(|| std::path::Path::new(&self.output).join(CONTROL_FILE))
    }

    /// Writes one operator command for the controller to pick up (within its 5-second sample).
    fn send_control(&mut self, value: &serde_json::Value) -> bool {
        let Some(path) = self.control_path() else {
            self.activity("the run directory is not known yet; try again in a moment");
            return false;
        };
        let body = serde_json::json!({ "docker_slots": value }).to_string();
        let temporary = path.with_extension("json.tmp");
        match std::fs::write(&temporary, body).and_then(|()| std::fs::rename(&temporary, &path)) {
            Ok(()) => true,
            Err(error) => {
                self.activity(format!("cannot write {}: {error}", path.display()));
                false
            }
        }
    }

    /// `+` / `-`: one more or one fewer Docker slot, from the last value asked for.
    fn adjust_slots(&mut self, delta: i64) {
        let base = self.requested_slots.unwrap_or(self.docker_slots);
        if base == 0 {
            self.activity("the Docker slots are not known yet; try again in a moment");
            return;
        }
        let wanted = base.saturating_add_signed(delta).clamp(1, MAX_DOCKER_SLOTS);
        if self.send_control(&serde_json::json!(wanted)) {
            self.requested_slots = Some(wanted);
            self.activity(format!(
                "docker slots → {wanted} (applies within 5 s; governor paused; a: back to auto)"
            ));
        }
    }

    /// `a`: give the Docker slots back to the governor.
    fn resume_governor(&mut self) {
        if self.send_control(&serde_json::json!("auto")) {
            self.requested_slots = None;
            self.activity("asked the governor to manage the Docker slots again");
        }
    }

    /// Live capacity line for the verification panel title.
    fn capacity(&self) -> String {
        let percent = |value: Option<f64>| {
            value.map_or_else(|| "–".to_owned(), |value| format!("{:.0}%", value * 100.0))
        };
        if self.docker_slots == 0 {
            return " Verification ".to_owned();
        }
        let pending = self
            .requested_slots
            .map_or_else(String::new, |wanted| format!(" → {wanted}"));
        format!(
            " Verification · docker {}/{}{pending} (+{} queued) · cpu {} · mem {} ",
            self.docker_active,
            self.docker_slots,
            self.docker_waiting,
            percent(self.cpu),
            percent(self.memory)
        )
    }

    fn summary(&self, elapsed: Duration) -> String {
        format!(
            "jsspector online: {} static, {} verified findings ({}/h), {} Satori issues, artifacts {}",
            self.static_done,
            self.verified_findings,
            self.issue_rate(elapsed),
            self.synced,
            if self.output.is_empty() {
                "unavailable"
            } else {
                &self.output
            }
        )
    }
}

struct TerminalSession;

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _result = disable_raw_mode();
        let _result = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn reader<R: Read + Send + 'static>(stream: R, sender: Sender<ControllerLine>, error: bool) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else {
                break;
            };
            let message = if error {
                ControllerLine::Error(line)
            } else {
                ControllerLine::Output(line)
            };
            if sender.send(message).is_err() {
                break;
            }
        }
    });
}

fn consume(receiver: &Receiver<ControllerLine>, state: &mut State) {
    while let Ok(line) = receiver.try_recv() {
        let value = match line {
            ControllerLine::Output(value) | ControllerLine::Error(value) => value,
        };
        if let Some(payload) = value.strip_prefix(EVENT_PREFIX) {
            match serde_json::from_str::<WireEvent>(payload) {
                Ok(event) => state.apply(event),
                Err(error) => state.activity(format!("invalid controller event: {error}")),
            }
        } else {
            state.activity(value);
        }
    }
}

/// A `width` × `height` rectangle centered in `area`, shrunk to fit.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

fn ratio(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (value as f64 / total as f64).clamp(0.0, 1.0)
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, state: &State, started: Instant) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let [
        header_area,
        progress_area,
        pipeline_area,
        improvement_area,
        activity_area,
        footer_area,
    ] = areas.as_ref()
    else {
        return;
    };

    let title = Line::from(vec![
        Span::styled(
            " JSSpector Online ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  {}  ·  discovered {}  ·  ",
            state.phase, state.discovered
        )),
        Span::styled(
            format!("issues {}/h", state.issue_rate(started.elapsed())),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  ·  elapsed {}s", started.elapsed().as_secs())),
    ]);
    frame.render_widget(
        Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
        *header_area,
    );

    let progress_total = state.total.max(state.discovered);
    let progress = Gauge::default()
        .block(
            Block::default()
                .title(" Static pass ")
                .borders(Borders::ALL),
        )
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(ratio(state.static_done, progress_total))
        .label(format!("{} / {}", state.static_done, progress_total));
    frame.render_widget(progress, *progress_area);

    let lane_rows = [
        Row::new(vec![
            "Deterministic".to_owned(),
            state.deterministic_queued.to_string(),
            state.deterministic_running.to_string(),
            state.deterministic_done.to_string(),
        ]),
        Row::new(vec![
            "Opus 5.5".to_owned(),
            state.ai_queued.to_string(),
            state.ai_running.to_string(),
            state.ai_done.to_string(),
        ]),
    ];
    let lane_table = Table::new(
        lane_rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(
        Row::new(["Lane", "Queued", "Active", "Done"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(state.capacity())
            .borders(Borders::ALL),
    );
    let outcome_rows = [
        Row::new(vec![
            "Verified findings".to_owned(),
            state.verified_findings.to_string(),
            format!("{} repos", state.verified_repositories),
        ]),
        Row::new(vec![
            "Proven fixes".to_owned(),
            state.fixes_proven.to_string(),
            format!("{} tried", state.fixes_attempted),
        ]),
        Row::new(vec![
            "Satori issues".to_owned(),
            state.synced.to_string(),
            String::new(),
        ]),
        Row::new(vec![
            "Operational failures".to_owned(),
            state.failures.to_string(),
            format!("{} timeouts", state.timeouts),
        ]),
    ];
    let outcome_table = Table::new(
        outcome_rows,
        [
            Constraint::Percentage(55),
            Constraint::Percentage(20),
            Constraint::Percentage(25),
        ],
    )
    .header(
        Row::new(["Result", "Count", "Detail"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" Outcomes ").borders(Borders::ALL));
    let pipeline_columns =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(*pipeline_area);
    let [lane_area, outcome_area] = pipeline_columns.as_ref() else {
        return;
    };
    frame.render_widget(lane_table, *lane_area);
    frame.render_widget(outcome_table, *outcome_area);

    let improvement = if state.performance.is_empty() {
        vec![Line::raw(
            "collecting… the first numbers appear after the first verifications",
        )]
    } else {
        state
            .performance
            .iter()
            .map(|value| Line::raw(value.clone()))
            .collect::<Vec<_>>()
    };
    frame.render_widget(
        Paragraph::new(improvement).block(
            Block::default()
                .title(" Where to improve ")
                .borders(Borders::ALL),
        ),
        *improvement_area,
    );

    let activity = state
        .activity
        .iter()
        .map(|value| Line::raw(value.clone()))
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(activity)
            .block(Block::default().title(" Activity ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        *activity_area,
    );

    let footer = if state.stopping {
        "Stopping safely… completed work will be resumable"
    } else {
        "q stop  ·  +/- docker slots  ·  a auto  ·  h help  ·  static findings never sync without verified exploitation"
    };
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        *footer_area,
    );
    if state.show_help {
        let area = centered(frame.area(), 90, HELP.len() as u16 + 2);
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(HELP.iter().map(|line| Line::raw(*line)).collect::<Vec<_>>()).block(
                Block::default()
                    .title(" Help · h, ? or Esc to close ")
                    .borders(Borders::ALL),
            ),
            area,
        );
    }
}

#[cfg(unix)]
fn interrupt(child: &mut Child) -> io::Result<()> {
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-INT", "--", &format!("-{pid}")])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        child.kill()
    }
}

#[cfg(unix)]
fn signal_group(pid: u32, signal: &str) -> io::Result<()> {
    let status = Command::new("kill")
        .args([signal, "--", &format!("-{pid}")])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "could not send {signal} to online controller group {pid}"
        )))
    }
}

#[cfg(unix)]
fn force_stop(child: &mut Child) -> io::Result<()> {
    signal_group(child.id(), "-KILL")
}

/// Run the controller without the dashboard while retaining bounded process-tree cancellation.
///
/// The controller gets its own process group. The foreground Rust process owns Ctrl-C and forwards
/// it, giving Python's handler a chance to terminate scanner and Claude sessions before it exits.
pub(crate) fn run_plain(mut command: Command) -> io::Result<ExitStatus> {
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn()?;

    #[cfg(unix)]
    {
        let pid = child.id();
        let interrupts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&interrupts);
        ctrlc::set_handler(move || {
            let signal = if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                "-INT"
            } else {
                "-KILL"
            };
            let _result = signal_group(pid, signal);
        })
        .map_err(|error| io::Error::other(format!("install Ctrl-C handler: {error}")))?;
    }

    child.wait()
}

#[cfg(not(unix))]
fn interrupt(child: &mut Child) -> io::Result<()> {
    child.kill()
}

#[cfg(not(unix))]
fn force_stop(child: &mut Child) -> io::Result<()> {
    child.kill()
}

/// Run the bundled controller and render its structured event stream.
pub(crate) fn run(mut command: Command) -> io::Result<ExitStatus> {
    command
        .env("JSSPECTOR_ONLINE_EVENTS", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("online controller stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("online controller stderr was not piped"))?;
    let (sender, receiver) = mpsc::channel();
    reader(stdout, sender.clone(), false);
    reader(stderr, sender, true);

    let mut state = State::new();
    let started = Instant::now();
    let status = {
        let _session = TerminalSession::enter()?;
        let backend = CrosstermBackend::new(io::stdout());
        let mut terminal = Terminal::new(backend)?;
        let mut finished_at = None;
        loop {
            consume(&receiver, &mut state);
            terminal.draw(|frame| draw(frame, &state, started))?;

            if event::poll(Duration::from_millis(80))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
                && state.on_key(key.code, key.modifiers) == KeyAction::Stop
            {
                if state.stopping {
                    state.activity("forcing the unresponsive controller to exit");
                    force_stop(&mut child)?;
                } else {
                    state.stopping = true;
                    state.phase = "Stopping".to_owned();
                    state.activity("stop requested; press again to force");
                    interrupt(&mut child)?;
                }
            }

            if let Some(status) = child.try_wait()? {
                consume(&receiver, &mut state);
                state.finished = true;
                if state.phase != "Interrupted" && state.phase != "Finished" {
                    state.phase = if status.success() {
                        "Finished".to_owned()
                    } else {
                        "Failed".to_owned()
                    };
                }
                let completed = *finished_at.get_or_insert_with(Instant::now);
                terminal.draw(|frame| draw(frame, &state, started))?;
                if completed.elapsed() >= Duration::from_millis(900) {
                    break status;
                }
            }
        }
    };
    if let Some(report) = &state.report {
        println!("{report}");
    }
    eprintln!("{}", state.summary(started.elapsed()));
    Ok(status)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn structured_events_drive_only_verified_metrics() {
        let mut state = State::new();
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"run_started","total":100,"run_id":"r1","output":"/tmp/r1"}"#,
            )
            .unwrap(),
        );
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"static_finished","repository":"a/b","outcome":"candidates"}"#,
            )
            .unwrap(),
        );
        state.apply(serde_json::from_str::<WireEvent>(
            r#"{"type":"verification_finished","repository":"a/b","lane":"ai","outcome":"verified","findings":2,"fix_attempted":true,"fix_proven":false}"#,
        ).unwrap());
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"sync_finished","repository":"a/b","success":true,"findings":2}"#,
            )
            .unwrap(),
        );
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"operational_failure","repository":"a/b","message":"Docker garbage collection failed"}"#,
            )
            .unwrap(),
        );
        assert_eq!(state.total, 100);
        assert_eq!(state.static_done, 1);
        assert_eq!(state.verified_repositories, 1);
        assert_eq!(state.verified_findings, 2);
        assert_eq!(state.synced, 2);
        assert_eq!(state.fixes_attempted, 1);
        assert_eq!(state.failures, 1);
    }

    #[test]
    fn resource_events_drive_the_capacity_line_and_keep_the_report() {
        let mut state = State::new();
        assert_eq!(state.capacity(), " Verification ");
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"resources","cpu":0.78,"memory":0.231,"active":9,"waiting":4,"slots":12}"#,
            )
            .unwrap(),
        );
        assert_eq!(
            state.capacity(),
            " Verification · docker 9/12 (+4 queued) · cpu 78% · mem 23% "
        );
        assert!(
            state.activity.is_empty(),
            "periodic samples must not flood the activity"
        );
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"resources","slots":13,"message":"governor: docker slots 12 → 13 (headroom)"}"#,
            )
            .unwrap(),
        );
        assert_eq!(state.docker_slots, 13);
        assert_eq!(state.activity.len(), 1);
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"calibration_finished","success":true,"report":"jsspector online calibration"}"#,
            )
            .unwrap(),
        );
        assert_eq!(state.phase, "Calibrated");
        assert_eq!(
            state.report.as_deref(),
            Some("jsspector online calibration")
        );
    }

    #[test]
    fn slot_shortcuts_write_the_control_file_and_wait_for_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = State::new();
        state.adjust_slots(1);
        assert!(
            state.requested_slots.is_none(),
            "nothing to adjust before the first sample"
        );
        state.output = dir.path().display().to_string();
        state.docker_slots = 9;
        let control = dir.path().join(CONTROL_FILE);
        let read = || std::fs::read_to_string(&control).unwrap();
        assert_eq!(
            state.on_key(KeyCode::Char('+'), KeyModifiers::NONE),
            KeyAction::Handled
        );
        assert_eq!(read(), r#"{"docker_slots":10}"#);
        state.on_key(KeyCode::Char('+'), KeyModifiers::NONE);
        state.on_key(KeyCode::Char('+'), KeyModifiers::NONE);
        assert_eq!(read(), r#"{"docker_slots":12}"#);
        assert_eq!(
            state.capacity(),
            " Verification · docker 0/9 → 12 (+0 queued) · cpu – · mem – "
        );
        state.apply(
            serde_json::from_str::<WireEvent>(r#"{"type":"resources","slots":12,"active":9}"#)
                .unwrap(),
        );
        assert_eq!(state.requested_slots, None);
        state.on_key(KeyCode::Char('-'), KeyModifiers::NONE);
        assert_eq!(read(), r#"{"docker_slots":11}"#);
        state.on_key(KeyCode::Char('a'), KeyModifiers::NONE);
        assert_eq!(read(), r#"{"docker_slots":"auto"}"#);
        assert_eq!(state.requested_slots, None);
        state.docker_slots = 1;
        state.on_key(KeyCode::Char('-'), KeyModifiers::NONE);
        assert_eq!(read(), r#"{"docker_slots":1}"#);
    }

    #[test]
    fn help_toggles_and_esc_closes_it_before_stopping() {
        let mut state = State::new();
        assert_eq!(
            state.on_key(KeyCode::Char('h'), KeyModifiers::NONE),
            KeyAction::Handled
        );
        assert!(state.show_help);
        let backend = TestBackend::new(120, 34);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, &state, Instant::now()))
            .unwrap();
        let rendered = terminal.backend().to_string();
        for expected in [
            "Help",
            "+ / -",
            "hand the slots back to the governor",
            "Bottleneck",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
        assert_eq!(
            state.on_key(KeyCode::Esc, KeyModifiers::NONE),
            KeyAction::Handled
        );
        assert!(!state.show_help);
        assert_eq!(
            state.on_key(KeyCode::Esc, KeyModifiers::NONE),
            KeyAction::Stop
        );
        assert_eq!(
            state.on_key(KeyCode::Char('q'), KeyModifiers::NONE),
            KeyAction::Stop
        );
        assert_eq!(
            state.on_key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            KeyAction::Stop
        );
    }

    #[test]
    fn improvement_panel_shows_the_controller_lines() {
        let mut state = State::new();
        state.apply(
            serde_json::from_str::<WireEvent>(
                r#"{"type":"performance","lines":["Docker time  issue 3% · timeout 34%","  of which   build/start 38%","Bottleneck   verification 72%","Lanes        deterministic 0.6 issues/slot-h (180 runs)"]}"#,
            )
            .unwrap(),
        );
        assert_eq!(state.performance.len(), 4);
        assert!(state.activity.is_empty());
        let backend = TestBackend::new(120, 34);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, &state, Instant::now()))
            .unwrap();
        let rendered = terminal.backend().to_string();
        for expected in [
            "Where to improve",
            "timeout 34%",
            "verification 72%",
            "deterministic 0.6",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn dashboard_renders_both_lanes_and_verified_outcomes() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = State::new();
        state.total = 1000;
        state.static_done = 420;
        state.deterministic_running = 2;
        state.ai_running = 2;
        state.verified_findings = 4;
        terminal
            .draw(|frame| draw(frame, &state, Instant::now()))
            .unwrap();
        let rendered = terminal.backend().to_string();
        for expected in [
            "JSSpector Online",
            "Verification",
            "Deterministic",
            "Opus 5.5",
            "Outcomes",
            "Verified findings",
            "issues –/h",
            "Where to improve",
            "collecting…",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn issue_rate_is_the_hourly_average_after_the_warm_up() {
        let mut state = State::new();
        state.verified_findings = 6;
        assert_eq!(state.issues_per_hour(Duration::from_secs(60)), None);
        assert_eq!(state.issue_rate(Duration::from_secs(60)), "–");
        assert_eq!(
            state.issues_per_hour(Duration::from_secs(30 * 60)),
            Some(12.0)
        );
        assert_eq!(state.issue_rate(Duration::from_secs(90 * 60)), "4.0");
        assert!(
            state
                .summary(Duration::from_secs(3600))
                .contains("6 verified findings (6.0/h)")
        );
        state.verified_findings = 0;
        assert_eq!(state.issue_rate(Duration::from_secs(3600)), "0.0");
    }
}
