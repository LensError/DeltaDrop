use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub blake3_hash: String,
    pub size: u64,
    pub mtime_ms: i64,
    pub rev: u64,
    pub deleted: bool,
}

#[derive(Debug, Clone)]
pub struct ConflictRow {
    pub id: u64,
    pub share_id: String,
    pub share_name: String,
    pub rel_path: String,
    pub conflict_path: String,
    pub time_label: String,
}

pub struct LocalStateDb {
    conn: Connection,
}

impl LocalStateDb {
    pub fn open(db_path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS share_state (
                share_id TEXT PRIMARY KEY,
                synced_version INTEGER NOT NULL,
                last_sync_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS baseline_files (
                share_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                blake3_hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime_ms INTEGER NOT NULL,
                rev INTEGER NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (share_id, rel_path)
            );
            CREATE TABLE IF NOT EXISTS conflicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_id TEXT NOT NULL,
                share_name TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                conflict_path TEXT NOT NULL,
                time_label TEXT NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    pub fn get_synced_version(&self, share_id: &str) -> anyhow::Result<u64> {
        let row: Option<i64> = self
            .conn
            .query_row(
                "SELECT synced_version FROM share_state WHERE share_id = ?1",
                params![share_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row.unwrap_or(0) as u64)
    }

    pub fn set_synced_version(
        &self,
        share_id: &str,
        version: u64,
        now_ms: i64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO share_state (share_id, synced_version, last_sync_ms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(share_id) DO UPDATE SET
                synced_version = excluded.synced_version,
                last_sync_ms = excluded.last_sync_ms",
            params![share_id, version as i64, now_ms],
        )?;
        Ok(())
    }

    pub fn list_baseline(&self, share_id: &str) -> anyhow::Result<HashMap<String, BaselineEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT rel_path, blake3_hash, size, mtime_ms, rev, deleted
             FROM baseline_files WHERE share_id = ?1",
        )?;
        let rows = stmt.query_map(params![share_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                BaselineEntry {
                    blake3_hash: r.get(1)?,
                    size: r.get::<_, i64>(2)? as u64,
                    mtime_ms: r.get(3)?,
                    rev: r.get::<_, i64>(4)? as u64,
                    deleted: r.get::<_, i64>(5)? != 0,
                },
            ))
        })?;
        let mut out = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            out.insert(k, v);
        }
        Ok(out)
    }

    pub fn replace_baseline(
        &mut self,
        share_id: &str,
        entries: &HashMap<String, BaselineEntry>,
    ) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM baseline_files WHERE share_id = ?1",
            params![share_id],
        )?;
        for (rel_path, e) in entries {
            tx.execute(
                "INSERT INTO baseline_files (share_id, rel_path, blake3_hash, size, mtime_ms, rev, deleted)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    share_id,
                    rel_path,
                    e.blake3_hash,
                    e.size as i64,
                    e.mtime_ms,
                    e.rev as i64,
                    if e.deleted { 1i64 } else { 0i64 }
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn remove_share(&self, share_id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM share_state WHERE share_id = ?1",
            params![share_id],
        )?;
        self.conn.execute(
            "DELETE FROM baseline_files WHERE share_id = ?1",
            params![share_id],
        )?;
        self.conn.execute(
            "DELETE FROM conflicts WHERE share_id = ?1",
            params![share_id],
        )?;
        Ok(())
    }

    pub fn push_conflict(
        &self,
        share_id: &str,
        share_name: &str,
        rel_path: &str,
        conflict_path: &str,
        time_label: &str,
    ) -> anyhow::Result<u64> {
        self.conn.execute(
            "INSERT INTO conflicts (share_id, share_name, rel_path, conflict_path, time_label)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![share_id, share_name, rel_path, conflict_path, time_label],
        )?;
        Ok(self.conn.last_insert_rowid() as u64)
    }

    pub fn list_conflicts(&self) -> anyhow::Result<Vec<ConflictRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, share_id, share_name, rel_path, conflict_path, time_label
             FROM conflicts ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ConflictRow {
                id: r.get::<_, i64>(0)? as u64,
                share_id: r.get(1)?,
                share_name: r.get(2)?,
                rel_path: r.get(3)?,
                conflict_path: r.get(4)?,
                time_label: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn remove_conflict(&self, id: u64) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM conflicts WHERE id = ?1", params![id as i64])?;
        Ok(())
    }
}
