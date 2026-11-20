use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone)]
pub struct ConflictRow {
    pub id: u64,
    pub folder_id: String,
    pub rel_path: String,
    pub conflict_path: String,
    pub time_label: String,
}

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub blake3_hash: String,
    pub mtime_ms: i64,
}

pub struct LocalManifest {
    conn: Connection,
}

impl LocalManifest {
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
            CREATE TABLE IF NOT EXISTS synced_files (
                folder_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                blake3_hash TEXT NOT NULL,
                mtime_ms INTEGER NOT NULL,
                PRIMARY KEY (folder_id, rel_path)
            );
            CREATE TABLE IF NOT EXISTS peer_versions (
                source_peer TEXT NOT NULL,
                folder_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                last_version INTEGER NOT NULL,
                PRIMARY KEY (source_peer, folder_id, rel_path)
            );
            CREATE TABLE IF NOT EXISTS peer_synced (
                peer_id TEXT NOT NULL,
                folder_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                blake3_hash TEXT NOT NULL,
                PRIMARY KEY (peer_id, folder_id, rel_path)
            );
            CREATE TABLE IF NOT EXISTS manifest_meta (
                key TEXT PRIMARY KEY,
                val INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conflicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_id TEXT NOT NULL,
                rel_path TEXT NOT NULL,
                conflict_path TEXT NOT NULL,
                time_label TEXT NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    pub fn get(&self, folder_id: &str, rel_path: &str) -> anyhow::Result<Option<ManifestEntry>> {
        let row = self
            .conn
            .query_row(
                "SELECT blake3_hash, mtime_ms FROM synced_files WHERE folder_id = ?1 AND rel_path = ?2",
                params![folder_id, rel_path],
                |r| {
                    Ok(ManifestEntry {
                        blake3_hash: r.get(0)?,
                        mtime_ms: r.get(1)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn upsert(
        &self,
        folder_id: &str,
        rel_path: &str,
        blake3_hash: &str,
        mtime_ms: i64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO synced_files (folder_id, rel_path, blake3_hash, mtime_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(folder_id, rel_path) DO UPDATE SET
                blake3_hash = excluded.blake3_hash,
                mtime_ms = excluded.mtime_ms",
            params![folder_id, rel_path, blake3_hash, mtime_ms],
        )?;
        Ok(())
    }

    pub fn remove(&self, folder_id: &str, rel_path: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM synced_files WHERE folder_id = ?1 AND rel_path = ?2",
            params![folder_id, rel_path],
        )?;
        Ok(())
    }

    pub fn list_folder(&self, folder_id: &str) -> anyhow::Result<Vec<(String, ManifestEntry)>> {
        let mut stmt = self.conn.prepare(
            "SELECT rel_path, blake3_hash, mtime_ms FROM synced_files WHERE folder_id = ?1",
        )?;
        let rows = stmt.query_map(params![folder_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                ManifestEntry {
                    blake3_hash: r.get(1)?,
                    mtime_ms: r.get(2)?,
                },
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_folder_prefix(&self, folder_id: &str, prefix: &str) -> anyhow::Result<Vec<String>> {
        let pattern = format!("{prefix}%");
        let mut stmt = self.conn.prepare(
            "SELECT rel_path FROM synced_files WHERE folder_id = ?1 AND rel_path LIKE ?2",
        )?;
        let rows = stmt.query_map(params![folder_id, pattern], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let rel = row?;
            if rel.starts_with(prefix) {
                out.push(rel);
            }
        }
        Ok(out)
    }

    pub fn next_delta_version(&self) -> anyhow::Result<u64> {
        let cur: Option<i64> = self
            .conn
            .query_row(
                "SELECT val FROM manifest_meta WHERE key = 'delta_seq'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let next = cur.unwrap_or(0) + 1;
        self.conn.execute(
            "INSERT INTO manifest_meta (key, val) VALUES ('delta_seq', ?1)
             ON CONFLICT(key) DO UPDATE SET val = excluded.val",
            params![next],
        )?;
        Ok(next as u64)
    }

    pub fn get_peer_version(
        &self,
        source_peer: &str,
        folder_id: &str,
        rel_path: &str,
    ) -> anyhow::Result<Option<u64>> {
        let row = self
            .conn
            .query_row(
                "SELECT last_version FROM peer_versions WHERE source_peer = ?1 AND folder_id = ?2 AND rel_path = ?3",
                params![source_peer, folder_id, rel_path],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        Ok(row.map(|v| v as u64))
    }

    pub fn set_peer_version(
        &self,
        source_peer: &str,
        folder_id: &str,
        rel_path: &str,
        version: u64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO peer_versions (source_peer, folder_id, rel_path, last_version)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(source_peer, folder_id, rel_path) DO UPDATE SET
                last_version = excluded.last_version",
            params![source_peer, folder_id, rel_path, version as i64],
        )?;
        Ok(())
    }

    pub fn get_peer_synced(
        &self,
        peer_id: &str,
        folder_id: &str,
        rel_path: &str,
    ) -> anyhow::Result<Option<String>> {
        let row = self
            .conn
            .query_row(
                "SELECT blake3_hash FROM peer_synced WHERE peer_id = ?1 AND folder_id = ?2 AND rel_path = ?3",
                params![peer_id, folder_id, rel_path],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(row)
    }

    pub fn set_peer_synced(
        &self,
        peer_id: &str,
        folder_id: &str,
        rel_path: &str,
        blake3_hash: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO peer_synced (peer_id, folder_id, rel_path, blake3_hash)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_id, folder_id, rel_path) DO UPDATE SET
                blake3_hash = excluded.blake3_hash",
            params![peer_id, folder_id, rel_path, blake3_hash],
        )?;
        Ok(())
    }

    pub fn remove_peer_synced_path(
        &self,
        peer_id: &str,
        folder_id: &str,
        rel_path: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM peer_synced WHERE peer_id = ?1 AND folder_id = ?2 AND rel_path = ?3",
            params![peer_id, folder_id, rel_path],
        )?;
        Ok(())
    }

    pub fn clear_peer_synced_folder(
        &self,
        peer_id: &str,
        folder_id: &str,
        prefix: Option<&str>,
    ) -> anyhow::Result<()> {
        match prefix {
            Some(pfx) => {
                let pattern = format!("{pfx}%");
                self.conn.execute(
                    "DELETE FROM peer_synced WHERE peer_id = ?1 AND folder_id = ?2 AND rel_path LIKE ?3",
                    params![peer_id, folder_id, pattern],
                )?;
            }
            None => {
                self.conn.execute(
                    "DELETE FROM peer_synced WHERE peer_id = ?1 AND folder_id = ?2",
                    params![peer_id, folder_id],
                )?;
            }
        }
        Ok(())
    }

    pub fn list_peer_synced_folder(
        &self,
        peer_id: &str,
        folder_id: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, String>> {
        let mut stmt = self.conn.prepare(
            "SELECT rel_path, blake3_hash FROM peer_synced WHERE peer_id = ?1 AND folder_id = ?2",
        )?;
        let rows = stmt.query_map(params![peer_id, folder_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = std::collections::HashMap::new();
        for row in rows {
            let (rel, hash) = row?;
            out.insert(rel, hash);
        }
        Ok(out)
    }

    pub fn find_by_hash_in_folder(
        &self,
        folder_id: &str,
        blake3_hash: &str,
    ) -> anyhow::Result<Option<String>> {
        let row = self
            .conn
            .query_row(
                "SELECT rel_path FROM synced_files WHERE folder_id = ?1 AND blake3_hash = ?2 LIMIT 1",
                params![folder_id, blake3_hash],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(row)
    }

    pub fn remove_folder(&self, folder_id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM synced_files WHERE folder_id = ?1",
            params![folder_id],
        )?;
        self.conn.execute(
            "DELETE FROM peer_versions WHERE folder_id = ?1",
            params![folder_id],
        )?;
        self.conn.execute(
            "DELETE FROM peer_synced WHERE folder_id = ?1",
            params![folder_id],
        )?;
        self.conn.execute(
            "DELETE FROM conflicts WHERE folder_id = ?1",
            params![folder_id],
        )?;
        Ok(())
    }

    pub fn push_conflict(
        &self,
        folder_id: &str,
        rel_path: &str,
        conflict_path: &str,
        time_label: &str,
    ) -> anyhow::Result<u64> {
        self.conn.execute(
            "INSERT INTO conflicts (folder_id, rel_path, conflict_path, time_label) VALUES (?1, ?2, ?3, ?4)",
            params![folder_id, rel_path, conflict_path, time_label],
        )?;
        Ok(self.conn.last_insert_rowid() as u64)
    }

    pub fn list_conflicts(&self) -> anyhow::Result<Vec<ConflictRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, folder_id, rel_path, conflict_path, time_label FROM conflicts ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ConflictRow {
                id: r.get::<_, i64>(0)? as u64,
                folder_id: r.get(1)?,
                rel_path: r.get(2)?,
                conflict_path: r.get(3)?,
                time_label: r.get(4)?,
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
