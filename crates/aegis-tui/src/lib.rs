pub mod app;
pub mod config_ui;
pub mod theme;
pub mod ui;

use std::io;
use std::path::Path;
use std::sync::Arc;
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
use aegis_core::runtime::RuntimeConfig;

use app::{App, LogViewer, ReplayEditor, Screen};

/// Run the live TUI dashboard, subscribing to broadcast events.
pub async fn run_live(
    mut rx: broadcast::Receiver<AuditEntry>,
    config: Option<Arc<RuntimeConfig>>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    io::stdout().execute(EnableMouseCapture)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new();

    loop {
        let table_height = calc_table_height(&terminal, &app)?;

        terminal.draw(|f| match app.screen {
            Screen::Live => ui::draw_live(f, &app),
            Screen::Config => config_ui::draw_config(f, &app),
            Screen::ReplayEdit => ui::draw_replay_editor(f, &app),
        })?;

        if crossterm::event::poll(Duration::from_millis(50))? {
            match app.screen {
                Screen::Live => {
                    if handle_input(&mut app, table_height, config.as_ref())? {
                        break;
                    }
                }
                Screen::Config => {
                    if handle_config_input(&mut app, config.as_ref())? {
                        break;
                    }
                }
                Screen::ReplayEdit => {
                    if handle_replay_edit_input(&mut app, config.as_ref())? {
                        break;
                    }
                }
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
        app.clear_expired_status();

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

    // Derive HTTP base URL from ws:// URL (e.g., ws://127.0.0.1:19002/api/live -> http://127.0.0.1:19002)
    let api_base = ws_url
        .replace("ws://", "http://")
        .replace("wss://", "https://")
        .split("/api/")
        .next()
        .unwrap_or("http://127.0.0.1:19002")
        .to_string();

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    io::stdout().execute(EnableMouseCapture)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new();
    app.remote_api_base = Some(api_base);

    loop {
        let table_height = calc_table_height(&terminal, &app)?;

        terminal.draw(|f| match app.screen {
            Screen::Live => ui::draw_live(f, &app),
            Screen::Config => config_ui::draw_config(f, &app),
            Screen::ReplayEdit => ui::draw_replay_editor(f, &app),
        })?;

        if crossterm::event::poll(Duration::from_millis(50))? {
            match app.screen {
                Screen::Live => {
                    if handle_input(&mut app, table_height, None)? {
                        break;
                    }
                }
                Screen::Config => {
                    if handle_config_input(&mut app, None)? {
                        break;
                    }
                }
                Screen::ReplayEdit => {
                    if handle_replay_edit_input(&mut app, None)? {
                        break;
                    }
                }
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
                // Search mode
                if viewer.search_active {
                    match key.code {
                        KeyCode::Esc => {
                            viewer.search_active = false;
                            viewer.search_query.clear();
                            viewer.scroll_offset = 0;
                            viewer.selected = 0;
                        }
                        KeyCode::Enter => {
                            viewer.search_active = false;
                        }
                        KeyCode::Backspace => {
                            viewer.search_query.pop();
                            viewer.scroll_offset = 0;
                            viewer.selected = 0;
                        }
                        KeyCode::Char(c) => {
                            viewer.search_query.push(c);
                            viewer.scroll_offset = 0;
                            viewer.selected = 0;
                        }
                        _ => {}
                    }
                } else if viewer.is_detail_open() {
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
                        KeyCode::Char('q') => viewer.should_quit = true,
                        KeyCode::Esc => {
                            if !viewer.search_query.is_empty() {
                                viewer.search_query.clear();
                                viewer.scroll_offset = 0;
                                viewer.selected = 0;
                            } else {
                                viewer.should_quit = true;
                            }
                        }
                        KeyCode::Char('/') => {
                            viewer.search_active = true;
                        }
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

/// Handle keyboard and mouse input on the live screen. Returns true if the app should quit.
fn handle_input(
    app: &mut App,
    table_height: usize,
    config: Option<&Arc<RuntimeConfig>>,
) -> anyhow::Result<bool> {
    match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => {
            // Search mode: capture keystrokes for the search query
            if app.search_active {
                match key.code {
                    KeyCode::Esc => {
                        app.search_active = false;
                        app.search_query.clear();
                        app.scroll_offset = 0;
                        app.selected = 0;
                    }
                    KeyCode::Enter => {
                        app.search_active = false;
                        // Keep query active, just exit input mode
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                        app.scroll_offset = 0;
                        app.selected = 0;
                    }
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                        app.scroll_offset = 0;
                        app.selected = 0;
                    }
                    _ => {}
                }
                return Ok(false);
            }

            if app.is_detail_open() {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.close_detail(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.detail_scroll = app.detail_scroll.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.detail_scroll += 1;
                    }
                    KeyCode::Char('r') => {
                        // Replay the selected request as-is
                        if let Some(idx) = app.detail_index {
                            let maybe_entry: Option<AuditEntry> = app.filtered_events().get(idx).copied().cloned();
                            if let Some(ref entry) = maybe_entry {
                                let cfg_ref = config;
                                let method = entry.method.clone();
                                let url = entry.url.clone();
                                let headers = entry.headers.clone();
                                let body = entry.body.clone();
                                app.status_message = Some(("Replaying...".into(), std::time::Instant::now()));
                                spawn_replay(cfg_ref, method, url, headers, body);
                            }
                        }
                    }
                    KeyCode::Char('R') => {
                        // Edit & replay
                        if let Some(idx) = app.detail_index {
                            let maybe_entry: Option<AuditEntry> = app.filtered_events().get(idx).copied().cloned();
                            if let Some(entry) = maybe_entry {
                                app.replay_editor = Some(ReplayEditor::from_entry(&entry));
                                app.screen = Screen::ReplayEdit;
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => app.should_quit = true,
                    KeyCode::Esc => {
                        if !app.search_query.is_empty() {
                            app.search_query.clear();
                            app.scroll_offset = 0;
                            app.selected = 0;
                        } else {
                            app.should_quit = true;
                        }
                    }
                    KeyCode::Char('/') => {
                        app.search_active = true;
                    }
                    KeyCode::Char('c') => {
                        if config.is_some() {
                            switch_to_config(app, config);
                        } else if app.remote_api_base.is_some() {
                            switch_to_config_remote(app);
                        }
                    }
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
                    KeyCode::Char('r') => {
                        // Replay selected request from list
                        let maybe_entry: Option<AuditEntry> = app.filtered_events().get(app.selected).copied().cloned();
                        if let Some(ref entry) = maybe_entry {
                            let cfg_ref = config;
                            let method = entry.method.clone();
                            let url = entry.url.clone();
                            let headers = entry.headers.clone();
                            let body = entry.body.clone();
                            app.status_message = Some(("Replaying...".into(), std::time::Instant::now()));
                            spawn_replay(cfg_ref, method, url, headers, body);
                        }
                    }
                    KeyCode::Char('R') => {
                        // Edit & replay selected request
                        let maybe_entry: Option<AuditEntry> = app.filtered_events().get(app.selected).copied().cloned();
                        if let Some(entry) = maybe_entry {
                            app.replay_editor = Some(ReplayEditor::from_entry(&entry));
                            app.screen = Screen::ReplayEdit;
                        }
                    }
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

/// Handle input on the replay edit screen.
fn handle_replay_edit_input(
    app: &mut App,
    config: Option<&Arc<RuntimeConfig>>,
) -> anyhow::Result<bool> {
    match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => {
            let Some(ref mut editor) = app.replay_editor else {
                app.screen = Screen::Live;
                return Ok(false);
            };

            match key.code {
                KeyCode::Esc => {
                    app.replay_editor = None;
                    app.screen = Screen::Live;
                }
                KeyCode::Tab => {
                    editor.focus = (editor.focus + 1) % 3;
                }
                KeyCode::BackTab => {
                    editor.focus = if editor.focus == 0 { 2 } else { editor.focus - 1 };
                }
                KeyCode::Enter => {
                    // Send the edited request
                    let method = editor.method.clone();
                    let url = editor.url.clone();
                    let headers = editor.headers.clone();
                    let body = if editor.body.is_empty() { None } else { Some(editor.body.clone()) };
                    app.status_message = Some(("Replaying...".into(), std::time::Instant::now()));
                    spawn_replay(config, method, url, headers, body);
                    app.replay_editor = None;
                    app.screen = Screen::Live;
                }
                KeyCode::Backspace => {
                    editor.focused_value_mut().pop();
                }
                KeyCode::Char(c) => {
                    if editor.focus == 0 {
                        // Method field: cycle through methods on any key
                        editor.cycle_method();
                    } else {
                        editor.focused_value_mut().push(c);
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(app.should_quit)
}

/// Spawn a background task to replay a request.
fn spawn_replay(
    config: Option<&Arc<RuntimeConfig>>,
    method: String,
    url_str: String,
    headers: std::collections::HashMap<String, String>,
    body: Option<String>,
) {
    let Some(cfg) = config else { return };
    let cfg = cfg.clone();

    tokio::spawn(async move {
        let engine = cfg.engine();

        let parsed_url = match url::Url::parse(&url_str) {
            Ok(u) => u,
            Err(_) => return,
        };
        let host = parsed_url.host_str().unwrap_or("unknown").to_string();
        let port = parsed_url.port().unwrap_or(if parsed_url.scheme() == "https" { 443 } else { 80 });
        let path = parsed_url.path().to_string();
        let content_type = headers.get("content-type").cloned();
        let body_bytes = body.as_ref().map(|b| bytes::Bytes::from(b.clone()));

        let ctx = aegis_core::analyzer::RequestContext {
            method: method.clone(),
            url: parsed_url.clone(),
            host: host.clone(),
            port,
            path,
            headers: headers.clone(),
            body: body_bytes.clone(),
            content_type: content_type.clone(),
        };

        let verdict = engine.evaluate_http(&ctx).await;

        let mut audit_entry = aegis_core::audit::AuditEntry::with_request(
            verdict.decision,
            verdict.reason.clone(),
            verdict.source.clone(),
            method,
            url_str,
            host,
            aegis_core::audit::Layer::Proxy,
            headers,
            body_bytes.as_deref(),
            content_type,
        );

        // If allowed, make the actual request
        if verdict.decision == aegis_core::decision::Decision::Allow {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default();

            let method = match ctx.method.to_uppercase().as_str() {
                "GET" => reqwest::Method::GET,
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "PATCH" => reqwest::Method::PATCH,
                "DELETE" => reqwest::Method::DELETE,
                "HEAD" => reqwest::Method::HEAD,
                "OPTIONS" => reqwest::Method::OPTIONS,
                _ => reqwest::Method::GET,
            };

            let mut request = client.request(method, parsed_url.as_str());
            for (k, v) in &ctx.headers {
                if k.to_lowercase() != "host" && k.to_lowercase() != "proxy-connection" {
                    request = request.header(k.as_str(), v.as_str());
                }
            }
            if let Some(ref b) = ctx.body {
                request = request.body(b.to_vec());
            }

            if let Ok(resp) = request.send().await {
                let status = resp.status().as_u16();
                let resp_ct = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let mut resp_headers = std::collections::HashMap::new();
                for (k, v) in resp.headers() {
                    if let Ok(val) = v.to_str() {
                        resp_headers.insert(k.to_string(), val.to_string());
                    }
                }
                let resp_body = resp.bytes().await.ok();
                audit_entry.set_response(status, resp_headers, resp_body.as_deref(), resp_ct.as_deref());
            }
        }

        cfg.audit().log(&audit_entry);
    });
}

/// Handle keyboard input on the config screen. Returns true if the app should quit.
fn handle_config_input(
    app: &mut App,
    config: Option<&Arc<RuntimeConfig>>,
) -> anyhow::Result<bool> {
    match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                KeyCode::Char('c') => {
                    app.screen = Screen::Live;
                    app.config_state.status_message = None;
                }
                KeyCode::Tab => {
                    app.config_state.focus = (app.config_state.focus + 1) % 2;
                    app.config_state.scroll = 0;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.config_state.focus == 0 {
                        // Preset list
                        if app.config_state.selected_preset > 0 {
                            app.config_state.selected_preset -= 1;
                        }
                    } else {
                        // Policy scroll
                        app.config_state.scroll = app.config_state.scroll.saturating_sub(1);
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.config_state.focus == 0 {
                        let max = app.config_state.preset_names.len().saturating_sub(1);
                        if app.config_state.selected_preset < max {
                            app.config_state.selected_preset += 1;
                        }
                    } else {
                        app.config_state.scroll += 1;
                    }
                }
                KeyCode::Enter => {
                    if app.config_state.focus == 0 {
                        apply_selected_preset(app, config);
                    }
                }
                _ => {}
            }
        }
        Event::Mouse(mouse) => {
            match mouse.kind {
                MouseEventKind::ScrollUp => {
                    if app.config_state.focus == 1 {
                        app.config_state.scroll = app.config_state.scroll.saturating_sub(1);
                    }
                }
                MouseEventKind::ScrollDown => {
                    if app.config_state.focus == 1 {
                        app.config_state.scroll += 1;
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(app.should_quit)
}

/// Load config state and switch to the config screen.
fn switch_to_config(app: &mut App, config: Option<&Arc<RuntimeConfig>>) {
    if let Some(cfg) = config {
        let cs = &mut app.config_state;
        cs.preset_names = cfg.list_presets();
        cs.active_preset = cfg.active_preset();
        cs.policy = Some(cfg.policy_snapshot());

        // Set selected to the active preset if found
        if let Some(ref active) = cs.active_preset {
            cs.selected_preset = cs.preset_names.iter()
                .position(|p| p == active)
                .unwrap_or(0);
        }

        // Secrets info
        if let Some(s) = cfg.secrets() {
            cs.secrets_count = s.secrets.len();
            cs.strip_env_count = s.strip_env.len();
        } else {
            cs.secrets_count = 0;
            cs.strip_env_count = 0;
        }

        cs.scroll = 0;
        cs.focus = 0;
        cs.status_message = None;
    }
    app.screen = Screen::Config;
}

/// Apply the currently selected preset.
fn apply_selected_preset(app: &mut App, config: Option<&Arc<RuntimeConfig>>) {
    let Some(cfg) = config else {
        // Try remote API in watch mode
        if app.remote_api_base.is_some() {
            apply_preset_remote(app);
        } else {
            app.config_state.status_message = Some("No RuntimeConfig available".into());
        }
        return;
    };

    let cs = &app.config_state;
    let Some(preset_name) = cs.preset_names.get(cs.selected_preset) else {
        return;
    };
    let preset_name = preset_name.clone();

    match cfg.apply_preset(&preset_name) {
        Ok(_rl) => {
            // Note: rate limiter rebuild is not handled from TUI since we don't have the handle.
            // The web API / proxy will pick up the new engine on next request.
            app.config_state.active_preset = Some(preset_name.clone());
            app.config_state.policy = Some(cfg.policy_snapshot());
            app.config_state.status_message = Some(format!("Applied preset: {preset_name}"));
        }
        Err(e) => {
            app.config_state.status_message = Some(format!("Error: {e}"));
        }
    }
}

/// Fetch config from remote API and switch to config screen (watch mode).
fn switch_to_config_remote(app: &mut App) {
    let Some(ref base) = app.remote_api_base else { return };
    let url = format!("{base}/api/config");

    match reqwest::blocking::get(&url) {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                let cs = &mut app.config_state;

                // Parse preset info
                if let Some(presets) = json.get("available_presets").and_then(|v| v.as_array()) {
                    cs.preset_names = presets
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                }
                cs.active_preset = json.get("preset").and_then(|v| v.as_str()).map(String::from);

                if let Some(ref active) = cs.active_preset {
                    cs.selected_preset = cs.preset_names.iter()
                        .position(|p| p == active)
                        .unwrap_or(0);
                }

                // Parse policy
                if let Some(policy_val) = json.get("policy") {
                    if let Ok(policy) = serde_json::from_value(policy_val.clone()) {
                        cs.policy = Some(policy);
                    }
                }

                // Parse secrets info
                if let Some(secrets) = json.get("secrets") {
                    cs.secrets_count = secrets.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    cs.strip_env_count = secrets.get("strip_env_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                }

                cs.scroll = 0;
                cs.focus = 0;
                cs.status_message = None;
            }
        }
        Err(e) => {
            app.config_state.status_message = Some(format!("Failed to fetch config: {e}"));
        }
    }
    app.screen = Screen::Config;
}

/// Apply preset via remote API (watch mode).
fn apply_preset_remote(app: &mut App) {
    let Some(ref base) = app.remote_api_base else { return };
    let Some(preset_name) = app.config_state.preset_names.get(app.config_state.selected_preset).cloned() else {
        return;
    };

    let url = format!("{base}/api/config/presets/apply");
    let client = reqwest::blocking::Client::new();
    match client.post(&url).json(&serde_json::json!({"preset": preset_name})).send() {
        Ok(resp) if resp.status().is_success() => {
            app.config_state.active_preset = Some(preset_name.clone());
            app.config_state.status_message = Some(format!("Applied preset: {preset_name}"));
            // Re-fetch policy to update the display
            if let Some(ref base) = app.remote_api_base {
                if let Ok(resp) = reqwest::blocking::get(&format!("{base}/api/config")) {
                    if let Ok(json) = resp.json::<serde_json::Value>() {
                        if let Some(policy_val) = json.get("policy") {
                            if let Ok(policy) = serde_json::from_value(policy_val.clone()) {
                                app.config_state.policy = Some(policy);
                            }
                        }
                    }
                }
            }
        }
        Ok(resp) => {
            app.config_state.status_message = Some(format!("Error: HTTP {}", resp.status()));
        }
        Err(e) => {
            app.config_state.status_message = Some(format!("Error: {e}"));
        }
    }
}

fn cleanup_terminal() -> anyhow::Result<()> {
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    io::stdout().execute(DisableMouseCapture)?;
    // show_cursor is handled by the alternate screen restore
    Ok(())
}
