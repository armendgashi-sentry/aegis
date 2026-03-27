use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::theme;

fn bg() -> Style {
    Style::default().bg(theme::BG)
}

fn card() -> Style {
    Style::default().bg(theme::BG_CARD)
}

pub fn draw_config(f: &mut Frame, app: &App) {
    f.render_widget(Clear, f.area());
    f.render_widget(Block::default().style(bg()), f.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(3),  // status message
            Constraint::Min(10),   // main content
            Constraint::Length(1),  // footer
        ])
        .split(f.area());

    draw_config_header(f, chunks[0]);
    draw_status_bar(f, chunks[1], app);

    // Split main content: preset list on left, policy display on right
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(40)])
        .split(chunks[2]);

    draw_preset_list(f, main[0], app);
    draw_policy_display(f, main[1], app);
    draw_config_footer(f, chunks[3], app);
}

fn draw_config_header(f: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG_HEADER))
        .style(Style::default().bg(theme::BG_HEADER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let s = Style::default().bg(theme::BG_HEADER);
    let line = Line::from(vec![
        Span::styled("  | ", s.fg(theme::BORDER)),
        Span::styled("AEGIS", s.fg(theme::CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" | ", s.fg(theme::BORDER)),
        Span::styled("CONFIG", s.fg(theme::YELLOW).add_modifier(Modifier::BOLD)),
    ]);

    f.render_widget(Paragraph::new(line).style(s), inner);
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let cs = &app.config_state;

    let mut spans = vec![Span::styled(" ", bg())];

    if let Some(ref preset) = cs.active_preset {
        spans.push(Span::styled(
            format!(" ACTIVE: {preset} "),
            Style::default().fg(theme::BG).bg(theme::GREEN).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled("  ", bg()));
    }

    if let Some(ref msg) = cs.status_message {
        spans.push(Span::styled(
            format!(" {msg} "),
            Style::default().fg(theme::YELLOW).bg(theme::BG),
        ));
    }

    f.render_widget(Paragraph::new(Line::from(spans)).style(bg()), area);
}

fn draw_preset_list(f: &mut Frame, area: Rect, app: &App) {
    let cs = &app.config_state;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if cs.focus == 0 { theme::CYAN } else { theme::BORDER }).bg(theme::BG_CARD))
        .title(Span::styled(
            " PRESETS ",
            Style::default().fg(theme::CYAN).bg(theme::BG_CARD),
        ))
        .style(card());

    let inner = block.inner(area);
    f.render_widget(block, area);

    if cs.preset_names.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "No presets found",
            Style::default().fg(theme::TEXT_DIM).bg(theme::BG_CARD),
        )))
        .alignment(Alignment::Center)
        .style(card());
        f.render_widget(msg, inner);
        return;
    }

    let lines: Vec<Line> = cs.preset_names.iter().enumerate().map(|(i, name)| {
        let is_active = cs.active_preset.as_deref() == Some(name.as_str());
        let is_selected = i == cs.selected_preset;

        let marker = if is_active { ">" } else { " " };
        let row_bg = if is_selected { theme::BG_SELECTED } else { theme::BG_CARD };
        let name_color = if is_active { theme::GREEN } else { theme::TEXT };

        Line::from(vec![
            Span::styled(
                format!(" {marker} "),
                Style::default().fg(theme::GREEN).bg(row_bg),
            ),
            Span::styled(
                name.to_string(),
                Style::default().fg(name_color).bg(row_bg).add_modifier(
                    if is_selected { Modifier::BOLD } else { Modifier::empty() }
                ),
            ),
            // Pad the rest
            Span::styled(
                " ".repeat(inner.width.saturating_sub(name.len() as u16 + 3) as usize),
                Style::default().bg(row_bg),
            ),
        ])
    }).collect();

    f.render_widget(
        Paragraph::new(lines).style(card()),
        inner,
    );
}

fn draw_policy_display(f: &mut Frame, area: Rect, app: &App) {
    let cs = &app.config_state;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if cs.focus == 1 { theme::CYAN } else { theme::BORDER }).bg(theme::BG_CARD))
        .title(Span::styled(
            " POLICY ",
            Style::default().fg(theme::CYAN).bg(theme::BG_CARD),
        ))
        .style(card());

    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(ref policy) = cs.policy else {
        let msg = Paragraph::new(Line::from(Span::styled(
            "No config loaded (RuntimeConfig not available)",
            Style::default().fg(theme::TEXT_DIM).bg(theme::BG_CARD),
        )))
        .alignment(Alignment::Center)
        .style(card());
        f.render_widget(msg, inner);
        return;
    };

    let s_label = Style::default().fg(theme::CYAN).bg(theme::BG_CARD);
    let s_value = Style::default().fg(theme::TEXT_BRIGHT).bg(theme::BG_CARD);
    let s_dim = Style::default().fg(theme::TEXT_DIM).bg(theme::BG_CARD);
    let s_section = Style::default().fg(theme::YELLOW).bg(theme::BG_CARD).add_modifier(Modifier::BOLD);

    let mut lines: Vec<Line> = Vec::new();

    // HTTP Policy
    lines.push(Line::from(Span::styled("  -- HTTP POLICY --", s_section)));
    lines.push(Line::from(""));

    let http = &policy.http;
    add_config_line(&mut lines, "  Safe Methods:    ", &http.methods.safe.join(", "), s_label, s_value);
    add_config_line(&mut lines, "  Inspect Methods: ", &http.methods.inspect.join(", "), s_label, s_value);

    if !http.methods.block.is_empty() {
        add_config_line(&mut lines, "  Blocked Methods: ", &http.methods.block.join(", "), s_label, Style::default().fg(theme::RED).bg(theme::BG_CARD));
    }

    if !http.payload.block_sql.is_empty() {
        add_config_line(&mut lines, "  Block SQL:       ", &http.payload.block_sql.join(", "), s_label, s_value);
    }
    if !http.payload.allow_sql.is_empty() {
        add_config_line(&mut lines, "  Allow SQL:       ", &http.payload.allow_sql.join(", "), s_label, s_dim);
    }
    if !http.payload.block_commands.is_empty() {
        add_config_line(&mut lines, "  Block Commands:  ", &http.payload.block_commands.join(", "), s_label, s_value);
    }
    add_config_line(&mut lines, "  Max Body Size:   ", &format!("{} bytes", http.max_request_body), s_label, s_value);

    // Shell Policy
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  -- SHELL POLICY --", s_section)));
    lines.push(Line::from(""));

    if !policy.shell.block_patterns.is_empty() {
        add_config_line(&mut lines, "  Block Patterns:  ", &policy.shell.block_patterns.join(", "), s_label, s_value);
    } else {
        add_config_line(&mut lines, "  Block Patterns:  ", "(none)", s_label, s_dim);
    }

    let sql_status = if policy.shell.block_sql_in_cli { "BLOCKED" } else { "ALLOWED" };
    let sql_color = if policy.shell.block_sql_in_cli { theme::GREEN } else { theme::RED };
    add_config_line(&mut lines, "  SQL in CLI:      ", sql_status, s_label, Style::default().fg(sql_color).bg(theme::BG_CARD));

    // Rate Limit
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  -- RATE LIMIT --", s_section)));
    lines.push(Line::from(""));

    let rl = &policy.rate_limit;
    add_config_line(&mut lines, "  Requests/sec:    ", &rl.requests_per_second.to_string(), s_label, s_value);
    add_config_line(&mut lines, "  Burst:           ", &rl.burst.to_string(), s_label, s_value);
    let pt = if rl.per_target { "YES" } else { "NO" };
    add_config_line(&mut lines, "  Per Target:      ", pt, s_label, s_value);

    // Secrets summary
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  -- SECRETS --", s_section)));
    lines.push(Line::from(""));

    if cs.secrets_count > 0 {
        add_config_line(&mut lines, "  Rules loaded:    ", &cs.secrets_count.to_string(), s_label, Style::default().fg(theme::PURPLE).bg(theme::BG_CARD));
        add_config_line(&mut lines, "  Env vars stripped: ", &cs.strip_env_count.to_string(), s_label, s_value);
    } else {
        add_config_line(&mut lines, "  Status:          ", "No secrets configured", s_label, s_dim);
    }

    // Apply scroll
    let visible: Vec<Line> = lines.into_iter().skip(cs.scroll).collect();

    f.render_widget(
        Paragraph::new(visible).style(card()).wrap(Wrap { trim: false }),
        inner,
    );
}

fn add_config_line<'a>(
    lines: &mut Vec<Line<'a>>,
    label: &'a str,
    value: &str,
    label_style: Style,
    value_style: Style,
) {
    lines.push(Line::from(vec![
        Span::styled(label, label_style),
        Span::styled(value.to_string(), value_style),
    ]));
}

fn draw_config_footer(f: &mut Frame, area: Rect, app: &App) {
    let cs = &app.config_state;
    let hint = if cs.focus == 0 {
        "[c] dashboard  [Tab] focus  [Up/Down] select  [Enter] apply preset  [q] quit"
    } else {
        "[c] dashboard  [Tab] focus  [Up/Down] scroll  [q] quit"
    };

    let line = Line::from(vec![
        Span::styled(format!(" AEGIS v{}", env!("CARGO_PKG_VERSION")), Style::default().fg(theme::TEXT_DIM).bg(theme::BG)),
        Span::styled(" | ", Style::default().fg(theme::BORDER).bg(theme::BG)),
        Span::styled(hint, Style::default().fg(theme::TEXT_DIM).bg(theme::BG)),
    ]);
    f.render_widget(Paragraph::new(line).style(bg()), area);
}
