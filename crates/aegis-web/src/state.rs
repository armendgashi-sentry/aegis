use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::Mutex;

use aegis_core::audit::AuditLogger;
use aegis_core::runtime::RuntimeConfig;
use aegis_proxy::rate_limiter::ProxyRateLimiter;
use aegis_sandbox::snapshot::{self, SnapshotBackend, SnapshotInfo};
use serde::Serialize;

/// Shared application state for the web UI API.
pub struct AppState {
    pub audit: AuditLogger,
    pub stats: Stats,
    pub audit_dir: Option<String>,
    pub config: Arc<RuntimeConfig>,
    pub rate_limiter: Option<Arc<RwLock<ProxyRateLimiter>>>,
    pub snapshots: Arc<Mutex<HashMap<String, SnapshotInfo>>>,
    pub snapshot_backend: Arc<dyn SnapshotBackend>,
}

impl AppState {
    pub fn new(
        audit: AuditLogger,
        config: Arc<RuntimeConfig>,
        rate_limiter: Option<Arc<RwLock<ProxyRateLimiter>>>,
    ) -> Self {
        let audit_dir = audit
            .log_path()
            .and_then(|p| {
                std::path::Path::new(p)
                    .parent()
                    .map(|d| d.to_string_lossy().to_string())
            })
            .or_else(|| Some(aegis_core::session::LOG_DIR.to_string()));

        Self {
            audit,
            stats: Stats::new(),
            audit_dir,
            config,
            rate_limiter,
            snapshots: Arc::new(Mutex::new(HashMap::new())),
            snapshot_backend: Arc::from(snapshot::detect_backend()),
        }
    }
}

/// Live statistics counters.
pub struct Stats {
    pub total: AtomicU64,
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
        }
    }

    pub fn record_allow(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_deny(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.denied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StatsSnapshot {
    pub total: u64,
    pub allowed: u64,
    pub denied: u64,
}
