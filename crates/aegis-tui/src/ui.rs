use aegis_core::audit::AuditEntry;
use aegis_core::decision::Decision;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::app::{App, Filter, LogViewer};
use crate::theme;

// ─── helpers ────────────────────────────────────────────────────────

fn bg() -> Style {
    Style::default().bg(theme::BG)
}

fn card() -> Style {
    Style::default().bg(theme::BG_CARD)
}

fn tbl_border(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG_CARD))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(theme::CYAN).bg(theme::BG_CARD),
        ))
        .style(card())
}

/// Returns how many data rows fit in the table area.
pub fn table_visible_height(table_area_height: u16) -> usize {
    // borders (2) + header (1) = 3 rows overhead
    table_area_height.saturating_sub(4) as usize
}

// ─── live dashboard ─────────────────────────────────────────────────

pub fn draw_live(f: &mut Frame, app: &App) {
    f.render_widget(Clear, f.area());
    f.render_widget(Block::default().style(bg()), f.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(5), // stats
            Constraint::Length(1), // filter bar
            Constraint::Min(8),   // event table
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_header(f, chunks[0], true);
    draw_stats(f, chunks[1], app.total, app.allowed, app.denied, app.rps);
    draw_filter_bar(f, chunks[2], app.filter, None, app.is_detail_open());

    let filtered = app.filtered_events();

    // If detail pane is open, split the table area
    if let Some(idx) = app.detail_index {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[3]);

        draw_event_table(f, parts[0], &filtered, app.scroll_offset, Some(app.selected));
        if let Some(entry) = filtered.get(idx) {
            draw_detail_pane(f, parts[1], entry, app.detail_scroll);
        }
    } else {
        draw_event_table(f, chunks[3], &filtered, app.scroll_offset, Some(app.selected));
    }

    draw_footer(f, chunks[4], app.total as usize, true);
}

// ─── log viewer ─────────────────────────────────────────────────────

pub fn draw_log_viewer(f: &mut Frame, viewer: &LogViewer) {
    f.render_widget(Clear, f.area());
    f.render_widget(Block::default().style(bg()), f.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, chunks[0], false);
    draw_stats(
        f, chunks[1],
        viewer.total() as u64, viewer.allowed() as u64, viewer.denied() as u64, 0,
    );
    draw_filter_bar(f, chunks[2], viewer.filter, Some(&viewer.file_name), viewer.is_detail_open());

    let filtered = viewer.filtered_entries();

    if let Some(idx) = viewer.detail_index {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[3]);

        draw_event_table(f, parts[0], &filtered, viewer.scroll_offset, Some(viewer.selected));
        if let Some(entry) = filtered.get(idx) {
            draw_detail_pane(f, parts[1], entry, viewer.detail_scroll);
        }
    } else {
        draw_event_table(f, chunks[3], &filtered, viewer.scroll_offset, Some(viewer.selected));
    }

    draw_footer(f, chunks[4], viewer.total(), false);
}

// ─── header ─────────────────────────────────────────────────────────

fn draw_header(f: &mut Frame, area: Rect, live: bool) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(theme::BORDER).bg(theme::BG_HEADER))
        .style(Style::default().bg(theme::BG_HEADER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let s = Style::default().bg(theme::BG_HEADER);

    let status = if live {
        Span::styled("● ONLINE", s.fg(theme::GREEN))
    } else {
        Span::styled("◆ LOG VIEWER", s.fg(theme::PURPLE))
    };

    let pad = " ".repeat(inner.width.saturating_sub(30) as usize);
    let line = Line::from(vec![
        Span::styled("  ┃ ", s.fg(theme::BORDER)),
        Span::styled("AEGIS", s.fg(theme::CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(" ┃ ", s.fg(theme::BORDER)),
        status,
        Span::styled(pad, s),
    ]);

    f.render_widget(Paragraph::new(line).style(s), inner);
}

// ─── stats ──────────────────────────────────────────────────────────

fn draw_stats(f: &mut Frame, area: Rect, total: u64, allowed: u64, denied: u64, rps: u64) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    draw_stat_box(f, cols[0], "TOTAL", &total.to_string(), theme::CYAN);
    draw_stat_box(f, cols[1], "ALLOWED", &allowed.to_string(), theme::GREEN);
    draw_stat_box(f, cols[2], "BLOCKED", &denied.to_string(), theme::RED);
    draw_stat_box(f, cols[3], "REQ/S", &rps.to_string(), theme::CYAN);
}

fn draw_stat_box(f: &mut Frame, area: Rect, label: &str, value: &str, accent: ratatui::style::Color) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER_DIM).bg(theme::BG_CARD))
        .style(card());

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 || inner.width < 4 {
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(inner);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            label,
            Style::default().fg(theme::TEXT_DIM).bg(theme::BG_CARD),
        )))
        .alignment(Alignment::Center)
        .style(card()),
        rows[0],
    );

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            value,
            Style::default().fg(accent).bg(theme::BG_CARD).add_modifier(Modifier::BOLD),
        )))
        .alignment(Alignment::Center)
        .style(card()),
        rows[1],
    );
}

// ─── filter bar ─────────────────────────────────────────────────────

fn draw_filter_bar(f: &mut Frame, area: Rect, current: Filter, file_name: Option<&str>, detail_open: bool) {
    let filters = [Filter::All, Filter::Allow, Filter::Block];
    let mut spans = vec![Span::styled(" ", bg())];

    for (i, filter) in filters.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" ", bg()));
        }
        let label = format!(" {} ", filter.label());
        if *filter == current {
            spans.push(Span::styled(
                label,
                Style::default().fg(theme::BG).bg(theme::CYAN).add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                label,
                Style::default().fg(theme::TEXT_DIM).bg(theme::BG),
            ));
        }
    }

    let hint = match (file_name, detail_open) {
        (Some(name), true) => format!("   ◆ {name}   [Enter] close  [↑↓] detail scroll  [Esc] back"),
        (Some(name), false) => format!("   ◆ {name}   [TAB] filter  [↑↓] scroll  [Enter] expand  [q] quit"),
        (_, true) => "   [Enter] close  [↑↓] scroll detail  [Esc] back".into(),
        (_, false) => "   [TAB] filter  [↑↓] scroll  [Enter] expand  [c] config  [q] quit".into(),
    };
    spans.push(Span::styled(hint, Style::default().fg(theme::TEXT_DIM).bg(theme::BG)));

    f.render_widget(Paragraph::new(Line::from(spans)).style(bg()), area);
}

// ─── event table ────────────────────────────────────────────────────

fn draw_event_table(
    f: &mut Frame,
    area: Rect,
    events: &[&AuditEntry],
    scroll_offset: usize,
    selected: Option<usize>,
) {
    if events.is_empty() {
        draw_empty_table(f, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("TIME"),
        Cell::from("STATUS"),
        Cell::from("METHOD"),
        Cell::from("TARGET"),
        Cell::from("SOURCE"),
        Cell::from("REASON"),
    ])
    .style(Style::default().fg(theme::CYAN).bg(theme::BG_CARD).add_modifier(Modifier::BOLD))
    .height(1);

    let visible_height = table_visible_height(area.height);

    let rows: Vec<Row> = events
        .iter()
        .skip(scroll_offset)
        .take(visible_height)
        .enumerate()
        .map(|(i, entry)| {
            let abs_idx = scroll_offset + i;
            let is_selected = selected == Some(abs_idx);

            let row_bg = if is_selected {
                theme::BG_SELECTED
            } else if abs_idx % 2 == 0 {
                theme::BG_CARD
            } else {
                theme::BG_ROW_ALT
            };

            let time = entry.timestamp.format("%H:%M:%S").to_string();

            let (status_text, status_fg) = match entry.decision {
                Decision::Allow => ("ALLOW", theme::GREEN),
                Decision::Deny => ("BLOCK", theme::RED),
            };

            let url_display = if entry.url.len() > 55 {
                format!("{}…", &entry.url[..54])
            } else {
                entry.url.clone()
            };

            let reason_display = if entry.reason.is_empty() {
                "—".to_string()
            } else if entry.reason.len() > 45 {
                format!("{}…", &entry.reason[..44])
            } else {
                entry.reason.clone()
            };

            let text_fg = if is_selected { theme::TEXT_BRIGHT } else { theme::TEXT };

            Row::new(vec![
                Cell::from(Span::styled(time, Style::default().fg(theme::TEXT_DIM).bg(row_bg))),
                Cell::from(Span::styled(
                    status_text,
                    Style::default().fg(status_fg).bg(row_bg).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    entry.method.clone(),
                    Style::default().fg(theme::YELLOW).bg(row_bg),
                )),
                Cell::from(Span::styled(url_display, Style::default().fg(text_fg).bg(row_bg))),
                Cell::from(Span::styled(
                    entry.source.clone(),
                    Style::default().fg(theme::PURPLE).bg(row_bg),
                )),
                Cell::from(Span::styled(reason_display, Style::default().fg(theme::TEXT_DIM).bg(row_bg))),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    let widths = [
        Constraint::Length(9),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Percentage(35),
        Constraint::Length(16),
        Constraint::Percentage(28),
    ];

    let total = events.len();
    let end = (scroll_offset + visible_height).min(total);
    let scroll_info = if total > visible_height {
        format!("EVENT LOG  {}-{}/{}", scroll_offset + 1, end, total)
    } else {
        format!("EVENT LOG  {total} entries")
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(tbl_border(&scroll_info))
        .highlight_style(Style::default().bg(theme::BG_SELECTED).fg(theme::TEXT_BRIGHT));

    f.render_widget(table, area);
}

fn draw_empty_table(f: &mut Frame, area: Rect) {
    let block = tbl_border("EVENT LOG");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled("WAITING FOR EVENTS…", Style::default().fg(theme::TEXT_DIM).bg(theme::BG_CARD))),
        Line::from(""),
        Line::from(Span::styled(
            "Send traffic through the proxy to see it here.",
            Style::default().fg(theme::TEXT_DIM).bg(theme::BG_CARD),
        )),
        Line::from(Span::styled(
            "curl --proxy http://127.0.0.1:19000 http://target/...",
            Style::default().fg(theme::CYAN).bg(theme::BG_CARD),
        )),
    ];

    f.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center).style(card()),
        inner,
    );
}

// ─── detail pane ────────────────────────────────────────────────────

fn draw_detail_pane(f: &mut Frame, area: Rect, entry: &AuditEntry, scroll: usize) {
    let (decision_text, decision_color) = match entry.decision {
        Decision::Allow => ("ALLOW", theme::GREEN),
        Decision::Deny => ("BLOCK", theme::RED),
    };

    let title = format!("REQUEST DETAIL — {decision_text}");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(decision_color).bg(theme::BG_CARD))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(decision_color).bg(theme::BG_CARD).add_modifier(Modifier::BOLD),
        ))
        .style(card());

    let inner = block.inner(area);
    f.render_widget(block, area);

    let s_label = Style::default().fg(theme::CYAN).bg(theme::BG_CARD);
    let s_value = Style::default().fg(theme::TEXT_BRIGHT).bg(theme::BG_CARD);
    let s_dim = Style::default().fg(theme::TEXT_DIM).bg(theme::BG_CARD);
    let s_highlight = Style::default()
        .fg(theme::RED)
        .bg(theme::BG_CARD)
        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);

    // Extract the blocked pattern from the reason for highlighting
    let blocked_pattern = extract_blocked_pattern(&entry.reason);

    let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string();

    let mut lines: Vec<Line<'_>> = Vec::new();

    // ── Raw HTTP request reconstruction ──
    lines.push(Line::from(Span::styled("  ── HTTP Request ──", s_label)));
    lines.push(Line::from(""));

    // Request line: METHOD URL
    let request_line = format!("  {} {}", entry.method, entry.url);
    if entry.decision == Decision::Deny && blocked_pattern.is_none() && entry.source == "builtin:http" {
        // Method itself is blocked - highlight the method
        lines.push(Line::from(vec![
            Span::styled("  ", s_value),
            Span::styled(&entry.method, s_highlight),
            Span::styled(format!(" {}", entry.url), s_value),
        ]));
    } else {
        lines.push(Line::from(Span::styled(request_line, s_value)));
    }

    // Headers
    if !entry.headers.is_empty() {
        let mut header_keys: Vec<_> = entry.headers.keys().collect();
        header_keys.sort();
        for key in header_keys {
            let val = &entry.headers[key];
            lines.push(Line::from(vec![
                Span::styled(format!("  {key}: "), s_dim),
                Span::styled(val.as_str(), s_dim),
            ]));
        }
    }

    // Body
    if let Some(ref body) = entry.body {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  ── Body ──", s_label)));

        if let Some(ref pattern) = blocked_pattern {
            // Render body with the blocked pattern highlighted
            for body_line in body.lines() {
                let spans = highlight_pattern(body_line, pattern, s_value, s_highlight);
                let mut line_spans = vec![Span::styled("  ", s_dim)];
                line_spans.extend(spans);
                lines.push(Line::from(line_spans));
            }
        } else {
            for body_line in body.lines() {
                lines.push(Line::from(Span::styled(format!("  {body_line}"), s_value)));
            }
        }
    } else if entry.method != "GET" && entry.method != "HEAD" && entry.method != "OPTIONS" {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  (no body)", s_dim)));
    }

    // Secrets Injected
    if !entry.secrets_applied.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  ── Secrets Injected ──",
            Style::default().fg(theme::PURPLE).bg(theme::BG_CARD),
        )));
        for secret in &entry.secrets_applied {
            let before_val = entry.headers.get(&secret.header)
                .map(|v| v.as_str())
                .unwrap_or("(not set)");
            lines.push(Line::from(vec![
                Span::styled("  Rule:   ", Style::default().fg(theme::PURPLE).bg(theme::BG_CARD)),
                Span::styled(&secret.rule_name, s_value),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Before: ", s_dim),
                Span::styled(format!("{}: {}", secret.header, before_val), s_dim),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  After:  ", Style::default().fg(theme::GREEN).bg(theme::BG_CARD)),
                Span::styled(
                    format!("{}: {}", secret.header, secret.masked_value),
                    Style::default().fg(theme::GREEN).bg(theme::BG_CARD),
                ),
            ]));
        }
    }

    // Reason
    if !entry.reason.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  ── Verdict ──", s_label)));
        lines.push(Line::from(vec![
            Span::styled("  ", s_dim),
            Span::styled(&entry.reason, Style::default().fg(decision_color).bg(theme::BG_CARD)),
        ]));
    }

    // Metadata
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  ── Metadata ──", s_label)));
    lines.push(Line::from(vec![
        Span::styled("  Source:    ", s_label),
        Span::styled(&entry.source, Style::default().fg(theme::PURPLE).bg(theme::BG_CARD)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Layer:     ", s_label),
        Span::styled(format!("{:?}", entry.layer), s_dim),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Timestamp: ", s_label),
        Span::styled(timestamp, s_dim),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  ID:        ", s_label),
        Span::styled(&entry.id, s_dim),
    ]));

    // Apply scroll
    let visible: Vec<Line<'_>> = lines.into_iter().skip(scroll).collect();

    f.render_widget(
        Paragraph::new(visible).style(card()).wrap(Wrap { trim: false }),
        inner,
    );
}

/// Extract the blocked pattern from a reason string for highlighting.
/// E.g., "SQL injection with destructive payload: DROP TABLE" → "DROP TABLE"
/// E.g., "Request body contains destructive command pattern: rm -rf" → "rm -rf"
/// E.g., "HTTP method DELETE is blocked by policy" → None (method-level block)
fn extract_blocked_pattern(reason: &str) -> Option<String> {
    // Pattern: "... pattern: <PATTERN>" or "... payload: <PATTERN>"
    for prefix in &["pattern: ", "payload: "] {
        if let Some(idx) = reason.find(prefix) {
            let pattern = reason[idx + prefix.len()..].trim();
            if !pattern.is_empty() {
                return Some(pattern.to_string());
            }
        }
    }
    None
}

/// Highlight occurrences of `pattern` within `text` (case-insensitive).
fn highlight_pattern<'a>(
    text: &'a str,
    pattern: &str,
    normal: Style,
    highlight: Style,
) -> Vec<Span<'a>> {
    let lower_text = text.to_lowercase();
    let lower_pattern = pattern.to_lowercase();
    let mut spans = Vec::new();
    let mut last = 0;

    for (start, _) in lower_text.match_indices(&lower_pattern) {
        if start > last {
            spans.push(Span::styled(&text[last..start], normal));
        }
        spans.push(Span::styled(
            &text[start..start + pattern.len()],
            highlight,
        ));
        last = start + pattern.len();
    }

    if last < text.len() {
        spans.push(Span::styled(&text[last..], normal));
    }

    if spans.is_empty() {
        spans.push(Span::styled(text, normal));
    }

    spans
}

// ─── footer ─────────────────────────────────────────────────────────

fn draw_footer(f: &mut Frame, area: Rect, total: usize, live: bool) {
    let mode = if live { "LIVE" } else { "LOG VIEWER" };
    let line = Line::from(vec![
        Span::styled(format!(" AEGIS v{}", env!("CARGO_PKG_VERSION")), Style::default().fg(theme::TEXT_DIM).bg(theme::BG)),
        Span::styled(" │ ", Style::default().fg(theme::BORDER).bg(theme::BG)),
        Span::styled(mode, Style::default().fg(theme::CYAN).bg(theme::BG)),
        Span::styled(" │ ", Style::default().fg(theme::BORDER).bg(theme::BG)),
        Span::styled(format!("{total} events"), Style::default().fg(theme::TEXT_DIM).bg(theme::BG)),
    ]);
    f.render_widget(Paragraph::new(line).style(bg()), area);
}
