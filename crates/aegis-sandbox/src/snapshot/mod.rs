pub mod git;

use std::path::Path;

/// Info about a created snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub method: String,
    pub root: String,
    pub timestamp: String,
    pub branch: Option<String>,
}

/// File-level diff entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileDiff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub summary: String,
}

/// Snapshot backend trait.
pub trait SnapshotBackend: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self, root: &Path) -> bool;
    fn create(&self, root: &Path) -> anyhow::Result<SnapshotInfo>;
    fn diff(&self, snapshot: &SnapshotInfo) -> anyhow::Result<FileDiff>;
    fn rollback(&self, snapshot: &SnapshotInfo) -> anyhow::Result<()>;
    fn commit(&self, snapshot: &SnapshotInfo, message: Option<&str>) -> anyhow::Result<()>;
}

/// Detect the best available snapshot backend.
pub fn detect_backend() -> Box<dyn SnapshotBackend> {
    Box::new(git::GitBackend)
}
