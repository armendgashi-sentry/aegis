pub mod app;
pub mod theme;
pub mod ui;

use std::io;
use std::path::Path;
use std::time::Duration;

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use futures_util::{FutureExt, StreamExt};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::broadcast;

use aegis_core::audit::{self, AuditEntry};

use app::{App, LogViewer};

/// Run the live TUI dashboard, subscribing to broadcast events.
pub async fn run_live(mut rx: broadcast::Receiver<AuditEntry>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    io::stdout().execute(EnableMouseCapture)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new();

    loop {
        let table_height = calc_table_height(&terminal, &app)?;

        terminal.draw(|f| ui::draw_live(f, &app))?;

        if crossterm::event::poll(Duration::from_millis(50))? {
            if handle_input(&mut app, table_height)? {
                break;
            }
        }

        // Drain broadcast events
        loop {
            match rx.try_recv() {
                Ok(entry) => app.push_event(entry),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(_)) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    app.should_quit = true;
                    break;
                }
            }
        }

        app.update_rps();

        if app.should_quit {
            break;
        }
    }

    cleanup_terminal()?;
    Ok(())
}

/// Run the live TUI by connecting to a running Aegis instance via WebSocket.
/// This doesn't start any servers — it's a client-only viewer.
pub async fn run_watch(ws_url: &str) -> anyhow::Result<()> {
    // Connect to WebSocket
    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url).await?;
    let (_, mut read) = ws_stream.split();

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    io::stdout().execute(EnableMouseCapture)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new();

    loop {
        let table_height = calc_table_height(&terminal, &app)?;

        terminal.draw(|f| ui::draw_live(f, &app))?;

        if crossterm::event::poll(Duration::from_millis(50))? {
            if handle_input(&mut app, table_height)? {
                break;
            }
        }

        // Drain WebSocket messages (non-blocking)
        loop {
            match read.next().now_or_never() {
                Some(Some(Ok(msg))) => {
                    if msg.is_text() {
                        let text = msg.into_data();
                        if let Ok(s) = String::from_utf8(text.to_vec()) {
                            if let Some(entry) = parse_ws_event(&s) {
                                app.push_event(entry);
                            }
                        }
                    }
                }
                Some(Some(Err(_))) => {
                    app.should_quit = true;
                    break;
                }
                Some(None) => {
                    // Stream ended
                    app.should_quit = true;
                    break;
                }
                None => break, // No message ready
            }
        }

        app.update_rps();

        if app.should_quit {
            break;
        }
    }

    cleanup_terminal()?;
    Ok(())
}

/// Parse a WebSocket event message into an AuditEntry.
/// Messages have the format: {"type": "event", "data": {...}}
fn parse_ws_event(text: &str) -> Option<AuditEntry> {
    let msg: serde_json::Value = serde_json::from_str(text).ok()?;
    if msg.get("type")?.as_str()? == "event" {
        let data = msg.get("data")?;
        serde_json::from_value(data.clone()).ok()
    } else {
        None
    }
}

/// Run the log viewer TUI for a specific audit log file.
pub fn run_log_viewer(path: &Path) -> anyhow::Result<()> {
    let entries = audit::read_audit_log(path)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    if entries.is_empty() {
        eprintln!("No entries found in {}", path.display());
        return Ok(());
    }

    let mut viewer = LogViewer::new(entries, file_name);

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    io::stdout().execute(EnableMouseCapture)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    loop {
        let table_height = {
            let size = terminal.size()?;
            let table_area_h = size.height.saturating_sub(10);
            if viewer.is_detail_open() {
                ui::table_visible_height(table_area_h / 2)
            } else {
                ui::table_visible_height(table_area_h)
            }
        };

        terminal.draw(|f| ui::draw_log_viewer(f, &viewer))?;

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if viewer.is_detail_open() {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => viewer.close_detail(),
                        KeyCode::Up | KeyCode::Char('k') => {
                            viewer.detail_scroll = viewer.detail_scroll.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            viewer.detail_scroll += 1;
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => viewer.should_quit = true,
                        KeyCode::Tab => viewer.cycle_filter(),
                        KeyCode::Up | KeyCode::Char('k') => viewer.scroll_up(),
                        KeyCode::Down | KeyCode::Char('j') => viewer.scroll_down(table_height),
                        KeyCode::PageUp => viewer.scroll_page_up(table_height),
                        KeyCode::PageDown => viewer.scroll_page_down(table_height, table_height),
                        KeyCode::Home => {
                            viewer.selected = 0;
                            viewer.scroll_offset = 0;
                        }
                        KeyCode::End => {
                            let max = viewer.filtered_entries().len().saturating_sub(1);
                            viewer.selected = max;
                            viewer.scroll_offset = max.saturating_sub(table_height.saturating_sub(1));
                        }
                        KeyCode::Enter => viewer.toggle_detail(),
                        _ => {}
                    }
                }
            }
            Event::Mouse(mouse) => {
                if !viewer.is_detail_open() {
                    match mouse.kind {
                        MouseEventKind::ScrollUp => viewer.scroll_up(),
                        MouseEventKind::ScrollDown => viewer.scroll_down(table_height),
                        _ => {}
                    }
                } else {
                    match mouse.kind {
                        MouseEventKind::ScrollUp => {
                            viewer.detail_scroll = viewer.detail_scroll.saturating_sub(1);
                        }
                        MouseEventKind::ScrollDown => {
                            viewer.detail_scroll += 1;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        if viewer.should_quit {
            break;
        }
    }

    cleanup_terminal()?;
    Ok(())
}

// --- Shared helpers ---

fn calc_table_height(
    terminal: &Terminal<CrosstermBackend<io::Stdout>>,
    app: &App,
) -> anyhow::Result<usize> {
    let size = terminal.size()?;
    let table_area_h = size.height.saturating_sub(10);
    Ok(if app.is_detail_open() {
        ui::table_visible_height(table_area_h / 2)
    } else {
        ui::table_visible_height(table_area_h)
    })
}

/// Handle keyboard and mouse input. Returns true if the app should quit.
fn handle_input(app: &mut App, table_height: usize) -> anyhow::Result<bool> {
    match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => {
            if app.is_detail_open() {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.close_detail(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.detail_scroll = app.detail_scroll.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.detail_scroll += 1;
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                    KeyCode::Tab => app.cycle_filter(),
                    KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
                    KeyCode::Down | KeyCode::Char('j') => app.scroll_down(table_height),
                    KeyCode::PageUp => app.scroll_page_up(table_height),
                    KeyCode::PageDown => app.scroll_page_down(table_height, table_height),
                    KeyCode::Home => {
                        app.selected = 0;
                        app.scroll_offset = 0;
                    }
                    KeyCode::End => {
                        let max = app.filtered_events().len().saturating_sub(1);
                        app.selected = max;
                        app.scroll_offset = max.saturating_sub(table_height.saturating_sub(1));
                    }
                    KeyCode::Enter => app.toggle_detail(),
                    _ => {}
                }
            }
        }
        Event::Mouse(mouse) => {
            if !app.is_detail_open() {
                match mouse.kind {
                    MouseEventKind::ScrollUp => app.scroll_up(),
                    MouseEventKind::ScrollDown => app.scroll_down(table_height),
                    _ => {}
                }
            } else {
                match mouse.kind {
                    MouseEventKind::ScrollUp => {
                        app.detail_scroll = app.detail_scroll.saturating_sub(1);
                    }
                    MouseEventKind::ScrollDown => {
                        app.detail_scroll += 1;
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(app.should_quit)
}

fn cleanup_terminal() -> anyhow::Result<()> {
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    io::stdout().execute(DisableMouseCapture)?;
    // show_cursor is handled by the alternate screen restore
    Ok(())
}
