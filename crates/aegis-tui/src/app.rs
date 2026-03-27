use std::collections::VecDeque;
use std::time::Instant;

use aegis_core::audit::AuditEntry;
use aegis_core::decision::Decision;
use aegis_core::policy::yaml_policy::YamlPolicy;

/// Which screen is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Live,
    Config,
    ReplayEdit,
}

/// Editable fields for replay.
pub struct ReplayEditor {
    /// 0=method, 1=url, 2=body
    pub focus: usize,
    pub method: String,
    pub url: String,
    pub body: String,
    pub headers: std::collections::HashMap<String, String>,
}

impl ReplayEditor {
    pub fn from_entry(entry: &AuditEntry) -> Self {
        Self {
            focus: 1, // start on URL
            method: entry.method.clone(),
            url: entry.url.clone(),
            body: entry.body.clone().unwrap_or_default(),
            headers: entry.headers.clone(),
        }
    }

    pub fn focused_label(&self) -> &str {
        match self.focus {
            0 => "METHOD",
            1 => "URL",
            2 => "BODY",
            _ => "",
        }
    }

    pub fn focused_value(&self) -> &str {
        match self.focus {
            0 => &self.method,
            1 => &self.url,
            2 => &self.body,
            _ => "",
        }
    }

    pub fn focused_value_mut(&mut self) -> &mut String {
        match self.focus {
            0 => &mut self.method,
            1 => &mut self.url,
            2 => &mut self.body,
            _ => &mut self.url,
        }
    }

    pub fn cycle_method(&mut self) {
        const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
        if let Some(idx) = METHODS.iter().position(|m| *m == self.method) {
            self.method = METHODS[(idx + 1) % METHODS.len()].to_string();
        } else {
            self.method = "GET".to_string();
        }
    }
}

/// State for the config screen.
pub struct ConfigState {
    pub preset_names: Vec<String>,
    pub selected_preset: usize,
    pub active_preset: Option<String>,
    pub policy: Option<YamlPolicy>,
    pub secrets_count: usize,
    pub strip_env_count: usize,
    pub scroll: usize,
    /// Which section is focused: 0=presets, 1=policy display
    pub focus: usize,
    pub status_message: Option<String>,
}

impl ConfigState {
    pub fn new() -> Self {
        Self {
            preset_names: Vec::new(),
            selected_preset: 0,
            active_preset: None,
            policy: None,
            secrets_count: 0,
            strip_env_count: 0,
            scroll: 0,
            focus: 0,
            status_message: None,
        }
    }
}

/// Which filter is active in the event table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    All,
    Allow,
    Block,
}

impl Filter {
    pub fn label(&self) -> &'static str {
        match self {
            Filter::All => "ALL",
            Filter::Allow => "ALLOW",
            Filter::Block => "BLOCK",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Filter::All => Filter::Allow,
            Filter::Allow => Filter::Block,
            Filter::Block => Filter::All,
        }
    }

    pub fn matches(&self, entry: &AuditEntry) -> bool {
        match self {
            Filter::All => true,
            Filter::Allow => entry.decision == Decision::Allow,
            Filter::Block => entry.decision == Decision::Deny,
        }
    }
}

/// TUI application state for live dashboard mode.
pub struct App {
    pub events: VecDeque<AuditEntry>,
    pub filter: Filter,
    pub total: u64,
    pub allowed: u64,
    pub denied: u64,
    pub scroll_offset: usize,
    pub max_events: usize,
    pub should_quit: bool,
    /// Index into filtered_events for the selected row (relative to scroll)
    pub selected: usize,
    /// If Some, show the detail pane for this filtered event index
    pub detail_index: Option<usize>,
    /// Scroll offset within the detail pane
    pub detail_scroll: usize,
    // RPS tracking
    rps_timestamps: VecDeque<Instant>,
    pub rps: u64,
    /// Current screen
    pub screen: Screen,
    /// Config screen state
    pub config_state: ConfigState,
    /// Search mode
    pub search_active: bool,
    pub search_query: String,
    /// Status message (e.g., "Replaying...", "Replay complete")
    pub status_message: Option<(String, Instant)>,
    /// Replay editor state (populated when user presses R)
    pub replay_editor: Option<ReplayEditor>,
}

impl App {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(1000),
            filter: Filter::All,
            total: 0,
            allowed: 0,
            denied: 0,
            scroll_offset: 0,
            max_events: 1000,
            should_quit: false,
            selected: 0,
            detail_index: None,
            detail_scroll: 0,
            rps_timestamps: VecDeque::new(),
            rps: 0,
            screen: Screen::Live,
            config_state: ConfigState::new(),
            search_active: false,
            search_query: String::new(),
            status_message: None,
            replay_editor: None,
        }
    }

    pub fn push_event(&mut self, entry: AuditEntry) {
        match entry.decision {
            Decision::Allow => self.allowed += 1,
            Decision::Deny => self.denied += 1,
        }
        self.total += 1;
        self.rps_timestamps.push_back(Instant::now());

        self.events.push_front(entry);
        if self.events.len() > self.max_events {
            self.events.pop_back();
        }
    }

    pub fn update_rps(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(1);
        while self.rps_timestamps.front().is_some_and(|t| *t < cutoff) {
            self.rps_timestamps.pop_front();
        }
        self.rps = self.rps_timestamps.len() as u64;
    }

    pub fn filtered_events(&self) -> Vec<&AuditEntry> {
        let query = self.search_query.to_lowercase();
        let has_search = !query.is_empty();
        self.events
            .iter()
            .filter(|e| self.filter.matches(e))
            .filter(|e| {
                if has_search {
                    e.url.to_lowercase().contains(&query)
                        || e.method.to_lowercase().contains(&query)
                        || e.reason.to_lowercase().contains(&query)
                        || e.source.to_lowercase().contains(&query)
                        || e.host.to_lowercase().contains(&query)
                } else {
                    true
                }
            })
            .collect()
    }

    /// Clear expired status messages (after 3 seconds).
    pub fn clear_expired_status(&mut self) {
        if let Some((_, when)) = &self.status_message {
            if when.elapsed() > std::time::Duration::from_secs(3) {
                self.status_message = None;
            }
        }
    }

    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.scroll_offset = 0;
        self.selected = 0;
        self.detail_index = None;
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            if self.selected < self.scroll_offset {
                self.scroll_offset = self.selected;
            }
        }
    }

    pub fn scroll_down(&mut self, visible_height: usize) {
        let max = self.filtered_events().len().saturating_sub(1);
        if self.selected < max {
            self.selected += 1;
            if self.selected >= self.scroll_offset + visible_height {
                self.scroll_offset = self.selected.saturating_sub(visible_height - 1);
            }
        }
    }

    pub fn scroll_page_up(&mut self, page_size: usize) {
        self.selected = self.selected.saturating_sub(page_size);
        self.scroll_offset = self.scroll_offset.saturating_sub(page_size);
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        }
    }

    pub fn scroll_page_down(&mut self, page_size: usize, visible_height: usize) {
        let max = self.filtered_events().len().saturating_sub(1);
        self.selected = (self.selected + page_size).min(max);
        if self.selected >= self.scroll_offset + visible_height {
            self.scroll_offset = self.selected.saturating_sub(visible_height - 1);
        }
    }

    pub fn toggle_detail(&mut self) {
        if self.detail_index.is_some() {
            self.detail_index = None;
            self.detail_scroll = 0;
        } else {
            self.detail_index = Some(self.selected);
            self.detail_scroll = 0;
        }
    }

    pub fn close_detail(&mut self) {
        self.detail_index = None;
        self.detail_scroll = 0;
    }

    pub fn is_detail_open(&self) -> bool {
        self.detail_index.is_some()
    }
}

/// TUI application state for log viewer mode.
pub struct LogViewer {
    pub entries: Vec<AuditEntry>,
    pub filter: Filter,
    pub scroll_offset: usize,
    pub should_quit: bool,
    pub file_name: String,
    pub selected: usize,
    pub detail_index: Option<usize>,
    pub detail_scroll: usize,
    pub search_active: bool,
    pub search_query: String,
}

impl LogViewer {
    pub fn new(entries: Vec<AuditEntry>, file_name: String) -> Self {
        Self {
            entries,
            filter: Filter::All,
            scroll_offset: 0,
            should_quit: false,
            file_name,
            selected: 0,
            detail_index: None,
            detail_scroll: 0,
            search_active: false,
            search_query: String::new(),
        }
    }

    pub fn total(&self) -> usize {
        self.entries.len()
    }

    pub fn allowed(&self) -> usize {
        self.entries.iter().filter(|e| e.decision == Decision::Allow).count()
    }

    pub fn denied(&self) -> usize {
        self.entries.iter().filter(|e| e.decision == Decision::Deny).count()
    }

    pub fn filtered_entries(&self) -> Vec<&AuditEntry> {
        let query = self.search_query.to_lowercase();
        let has_search = !query.is_empty();
        self.entries
            .iter()
            .filter(|e| self.filter.matches(e))
            .filter(|e| {
                if has_search {
                    e.url.to_lowercase().contains(&query)
                        || e.method.to_lowercase().contains(&query)
                        || e.reason.to_lowercase().contains(&query)
                        || e.source.to_lowercase().contains(&query)
                        || e.host.to_lowercase().contains(&query)
                } else {
                    true
                }
            })
            .collect()
    }

    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.scroll_offset = 0;
        self.selected = 0;
        self.detail_index = None;
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            if self.selected < self.scroll_offset {
                self.scroll_offset = self.selected;
            }
        }
    }

    pub fn scroll_down(&mut self, visible_height: usize) {
        let max = self.filtered_entries().len().saturating_sub(1);
        if self.selected < max {
            self.selected += 1;
            if self.selected >= self.scroll_offset + visible_height {
                self.scroll_offset = self.selected.saturating_sub(visible_height - 1);
            }
        }
    }

    pub fn scroll_page_up(&mut self, page_size: usize) {
        self.selected = self.selected.saturating_sub(page_size);
        self.scroll_offset = self.scroll_offset.saturating_sub(page_size);
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        }
    }

    pub fn scroll_page_down(&mut self, page_size: usize, visible_height: usize) {
        let max = self.filtered_entries().len().saturating_sub(1);
        self.selected = (self.selected + page_size).min(max);
        if self.selected >= self.scroll_offset + visible_height {
            self.scroll_offset = self.selected.saturating_sub(visible_height - 1);
        }
    }

    pub fn toggle_detail(&mut self) {
        if self.detail_index.is_some() {
            self.detail_index = None;
            self.detail_scroll = 0;
        } else {
            self.detail_index = Some(self.selected);
            self.detail_scroll = 0;
        }
    }

    pub fn close_detail(&mut self) {
        self.detail_index = None;
        self.detail_scroll = 0;
    }

    pub fn is_detail_open(&self) -> bool {
        self.detail_index.is_some()
    }
}
