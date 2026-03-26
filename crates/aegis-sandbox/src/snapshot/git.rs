use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context};

use super::{FileDiff, SnapshotBackend, SnapshotInfo};

/// Git-based snapshot backend. Cross-platform, works whenever git is present.
pub struct GitBackend;

impl GitBackend {
    /// Run a git command in the given directory and return stdout on success.
    fn git(root: &Path, args: &[&str]) -> anyhow::Result<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .with_context(|| format!("failed to run git {}", args.join(" ")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git {} failed: {}", args.join(" "), stderr.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get the current branch name (or HEAD commit if detached).
    fn current_branch(root: &Path) -> String {
        // Try symbolic-ref first (works for normal branch checkout)
        if let Ok(branch) = Self::git(root, &["symbolic-ref", "--short", "HEAD"]) {
            return branch;
        }
        // Detached HEAD — try the commit hash
        if let Ok(hash) = Self::git(root, &["rev-parse", "--short", "HEAD"]) {
            return hash;
        }
        // No commits yet (orphan) — return the default branch name
        "main".to_string()
    }

    /// Check if the repo has at least one commit.
    fn has_commits(root: &Path) -> bool {
        Self::git(root, &["rev-parse", "HEAD"]).is_ok()
    }

    /// Check if working tree is dirty (uncommitted changes).
    fn is_dirty(root: &Path) -> anyhow::Result<bool> {
        let status = Self::git(root, &["status", "--porcelain"])?;
        Ok(!status.is_empty())
    }
}

impl SnapshotBackend for GitBackend {
    fn name(&self) -> &str {
        "git"
    }

    fn is_available(&self, root: &Path) -> bool {
        // Check that git is installed and the directory is inside a git repo
        Self::git(root, &["rev-parse", "--git-dir"]).is_ok()
    }

    fn create(&self, root: &Path) -> anyhow::Result<SnapshotInfo> {
        let root = root
            .canonicalize()
            .with_context(|| format!("cannot resolve root path: {}", root.display()))?;

        let id = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let original_branch = Self::current_branch(&root);
        let branch_name = format!("aegis-snapshot-{id}");
        let timestamp = chrono::Utc::now().to_rfc3339();
        let has_commits = Self::has_commits(&root);

        if has_commits {
            // If the working tree is dirty, stash changes so we can switch branches
            let was_dirty = Self::is_dirty(&root)?;
            if was_dirty {
                Self::git(&root, &["stash", "push", "-m", "aegis: pre-snapshot stash"])?;
            }

            // Create the snapshot branch from the current HEAD
            Self::git(&root, &["checkout", "-b", &branch_name])?;

            // Restore stashed changes if there were any
            if was_dirty {
                Self::git(&root, &["stash", "pop"])?;
            }
        } else {
            // No commits yet (orphan branch) — create initial commit first
            Self::git(&root, &["add", "-A"])?;
            let status = Self::git(&root, &["status", "--porcelain"])?;
            if !status.is_empty() {
                Self::git(&root, &["commit", "-m", "aegis: initial commit (pre-snapshot)"])?;
            } else {
                Self::git(&root, &["commit", "--allow-empty", "-m", "aegis: initial commit (pre-snapshot)"])?;
            }
            // Now create the snapshot branch
            Self::git(&root, &["checkout", "-b", &branch_name])?;
        }

        // Stage everything and commit as the pre-agent snapshot
        Self::git(&root, &["add", "-A"])?;

        // Only commit if there is something to commit
        let status = Self::git(&root, &["status", "--porcelain"])?;
        if !status.is_empty() {
            Self::git(
                &root,
                &["commit", "-m", "aegis-snapshot: pre-agent state"],
            )?;
        } else {
            // Nothing staged — create an empty commit as a marker
            Self::git(
                &root,
                &[
                    "commit",
                    "--allow-empty",
                    "-m",
                    "aegis-snapshot: pre-agent state",
                ],
            )?;
        }

        tracing::info!(
            "Snapshot created: {} on branch {} (original: {})",
            id,
            branch_name,
            original_branch
        );

        Ok(SnapshotInfo {
            id,
            method: "git".to_string(),
            root: root.to_string_lossy().to_string(),
            timestamp,
            branch: Some(format!("{original_branch}:{branch_name}")),
        })
    }

    fn diff(&self, snapshot: &SnapshotInfo) -> anyhow::Result<FileDiff> {
        let root = Path::new(&snapshot.root);

        // The snapshot branch has the pre-agent commit at HEAD.
        // Any changes the agent made are in the working tree (unstaged/untracked).
        // Use `git diff HEAD --name-status` for tracked changes and
        // `git ls-files --others --exclude-standard` for new files.

        // Stage everything so diff HEAD catches all changes
        Self::git(root, &["add", "-A"])?;

        let diff_output = Self::git(root, &["diff", "--cached", "--name-status", "HEAD"])?;

        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        for line in diff_output.lines() {
            let parts: Vec<&str> = line.splitn(2, '\t').collect();
            if parts.len() < 2 {
                continue;
            }
            let status = parts[0].trim();
            let file = parts[1].trim().to_string();
            match status {
                "A" => added.push(file),
                "M" => modified.push(file),
                "D" => deleted.push(file),
                s if s.starts_with('R') => {
                    // Rename — treat as delete + add
                    let rename_parts: Vec<&str> = file.splitn(2, '\t').collect();
                    if rename_parts.len() == 2 {
                        deleted.push(rename_parts[0].to_string());
                        added.push(rename_parts[1].to_string());
                    } else {
                        modified.push(file);
                    }
                }
                _ => modified.push(file),
            }
        }

        // Unstage so we don't leave things in a weird state
        let _ = Self::git(root, &["reset", "HEAD"]);

        let total = added.len() + modified.len() + deleted.len();
        let summary = format!(
            "{} files changed, {} added, {} modified, {} deleted",
            total,
            added.len(),
            modified.len(),
            deleted.len(),
        );

        Ok(FileDiff {
            added,
            modified,
            deleted,
            summary,
        })
    }

    fn rollback(&self, snapshot: &SnapshotInfo) -> anyhow::Result<()> {
        let root = Path::new(&snapshot.root);

        let (original_branch, _snapshot_branch) = parse_branches(snapshot)?;

        // Discard all agent changes: restore working tree to snapshot commit
        Self::git(root, &["checkout", "."])?;
        Self::git(root, &["clean", "-fd"])?;

        // Switch back to original branch
        Self::git(root, &["checkout", &original_branch])?;

        tracing::info!("Rolled back to pre-agent state, returned to branch {}", original_branch);
        Ok(())
    }

    fn commit(&self, snapshot: &SnapshotInfo, message: Option<&str>) -> anyhow::Result<()> {
        let root = Path::new(&snapshot.root);

        let (original_branch, _snapshot_branch) = parse_branches(snapshot)?;

        let msg = message.unwrap_or("aegis: agent changes accepted");

        // Stage and commit all agent changes on the snapshot branch
        Self::git(root, &["add", "-A"])?;

        let status = Self::git(root, &["status", "--porcelain"])?;
        if !status.is_empty() {
            Self::git(root, &["commit", "-m", msg])?;
        }

        // Switch back to original branch and merge the snapshot branch
        Self::git(root, &["checkout", &original_branch])?;

        // Merge with --no-ff to preserve history
        let merge_msg = format!("Merge aegis snapshot: {}", snapshot.id);
        Self::git(root, &["merge", "--no-ff", "-m", &merge_msg, &_snapshot_branch])?;

        tracing::info!("Accepted agent changes and merged to {}", original_branch);
        Ok(())
    }
}

/// Parse the "original:snapshot" branch field.
fn parse_branches(snapshot: &SnapshotInfo) -> anyhow::Result<(String, String)> {
    let branch_info = snapshot
        .branch
        .as_deref()
        .context("snapshot has no branch information")?;

    let parts: Vec<&str> = branch_info.splitn(2, ':').collect();
    if parts.len() != 2 {
        bail!(
            "invalid branch format in snapshot info: expected 'original:snapshot', got '{}'",
            branch_info
        );
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a temporary git repo with an initial commit.
    fn setup_git_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        Command::new("git")
            .args(["init"])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@aegis.dev"])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Aegis Test"])
            .current_dir(root)
            .output()
            .unwrap();
        fs::write(root.join("README.md"), "# Test\n").unwrap();
        Command::new("git")
            .args(["add", "-A"])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(root)
            .output()
            .unwrap();
        dir
    }

    #[test]
    fn test_is_available() {
        let dir = setup_git_repo();
        let backend = GitBackend;
        assert!(backend.is_available(dir.path()));
    }

    #[test]
    fn test_create_and_diff_no_changes() {
        let dir = setup_git_repo();
        let backend = GitBackend;

        let snap = backend.create(dir.path()).unwrap();
        assert_eq!(snap.method, "git");
        assert!(snap.branch.is_some());

        let diff = backend.diff(&snap).unwrap();
        assert!(diff.added.is_empty());
        assert!(diff.modified.is_empty());
        assert!(diff.deleted.is_empty());
    }

    #[test]
    fn test_create_diff_rollback() {
        let dir = setup_git_repo();
        let root = dir.path();
        let backend = GitBackend;

        let snap = backend.create(root).unwrap();

        // Simulate agent changes
        fs::write(root.join("agent_file.txt"), "agent was here").unwrap();
        fs::write(root.join("README.md"), "# Modified by agent\n").unwrap();

        let diff = backend.diff(&snap).unwrap();
        assert!(diff.added.contains(&"agent_file.txt".to_string()));
        assert!(diff.modified.contains(&"README.md".to_string()));

        // Rollback
        backend.rollback(&snap).unwrap();

        // Verify files are restored
        assert!(!root.join("agent_file.txt").exists());
        let readme = fs::read_to_string(root.join("README.md")).unwrap();
        assert_eq!(readme, "# Test\n");
    }

    #[test]
    fn test_create_diff_commit() {
        let dir = setup_git_repo();
        let root = dir.path();
        let backend = GitBackend;

        let snap = backend.create(root).unwrap();

        // Simulate agent changes
        fs::write(root.join("new_file.txt"), "created by agent").unwrap();

        // Commit (accept changes)
        backend
            .commit(&snap, Some("accept agent work"))
            .unwrap();

        // Verify we're back on the original branch and the file persists
        let branch = GitBackend::current_branch(root);
        assert!(!branch.starts_with("aegis-snapshot-"));
        assert!(root.join("new_file.txt").exists());
    }
}
