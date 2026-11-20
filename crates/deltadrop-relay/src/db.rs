use std::path::Path;

use rusqlite::{params, Connection};

pub fn init_db(db_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        CREATE TABLE IF NOT EXISTS pending_deltas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_peer TEXT NOT NULL,
            target_peer TEXT NOT NULL,
            folder_id TEXT NOT NULL,
            rel_path TEXT NOT NULL,
            op_type TEXT NOT NULL,
            blake3_hash TEXT NOT NULL,
            base_hash TEXT,
            delta_version INTEGER NOT NULL DEFAULT 0,
            chunk_ids_json TEXT NOT NULL DEFAULT '[]',
            raw_size INTEGER NOT NULL,
            zst_size INTEGER NOT NULL,
            mtime_ms INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            blob_name TEXT NOT NULL,
            UNIQUE(target_peer, folder_id, rel_path)
        );
        CREATE TABLE IF NOT EXISTS chunks (
            chunk_id TEXT PRIMARY KEY,
            size_bytes INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS delta_chunks (
            delta_id INTEGER NOT NULL,
            chunk_id TEXT NOT NULL,
            PRIMARY KEY (delta_id, chunk_id)
        );
        CREATE INDEX IF NOT EXISTS idx_delta_chunks_chunk ON delta_chunks(chunk_id);
        CREATE TABLE IF NOT EXISTS folder_indices (
            source_peer TEXT NOT NULL,
            folder_id TEXT NOT NULL,
            subdirs_json TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY (source_peer, folder_id)
        );
        CREATE TABLE IF NOT EXISTS pull_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_peer TEXT NOT NULL,
            target_peer TEXT NOT NULL,
            folder_id TEXT NOT NULL,
            subdir TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            UNIQUE(target_peer, folder_id, subdir)
        );
        CREATE TABLE IF NOT EXISTS peers (
            peer_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            last_seen_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            salt TEXT NOT NULL,
            auth_hash TEXT NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_id TEXT,
            expires_at_ms INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE TABLE IF NOT EXISTS devices (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            encrypted_name TEXT NOT NULL,
            os TEXT NOT NULL,
            last_seen_ms INTEGER NOT NULL,
            online INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, device_id)
        );
        CREATE TABLE IF NOT EXISTS folder_manifests (
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            folder_id TEXT NOT NULL,
            encrypted_meta_b64 TEXT NOT NULL,
            version INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY (user_id, device_id, folder_id)
        );
        CREATE TABLE IF NOT EXISTS sync_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            source_device_id TEXT NOT NULL,
            target_device_id TEXT NOT NULL,
            folder_id TEXT NOT NULL,
            chunk_hashes_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sync_req_src ON sync_requests(user_id, source_device_id, status);
        CREATE TABLE IF NOT EXISTS user_chunks (
            user_id TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            pending_peers_json TEXT NOT NULL DEFAULT '[]',
            created_at_ms INTEGER NOT NULL,
            last_accessed_ms INTEGER NOT NULL,
            PRIMARY KEY (user_id, chunk_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_chunks_lru ON user_chunks(last_accessed_ms);
        ",
    )?;
    let cols: Vec<String> = conn
        .prepare("PRAGMA table_info(pending_deltas)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(Result::ok)
        .collect();
    if !cols.iter().any(|c| c == "base_hash") {
        conn.execute("ALTER TABLE pending_deltas ADD COLUMN base_hash TEXT", [])?;
    }
    if !cols.iter().any(|c| c == "delta_version") {
        conn.execute(
            "ALTER TABLE pending_deltas ADD COLUMN delta_version INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !cols.iter().any(|c| c == "chunk_ids_json") {
        conn.execute(
            "ALTER TABLE pending_deltas ADD COLUMN chunk_ids_json TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
    Ok(conn)
}

pub fn current_usage(conn: &Connection) -> rusqlite::Result<(u64, u64)> {
    let (count, blob_bytes): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(zst_size), 0) FROM pending_deltas",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let chunk_bytes: i64 = conn.query_row(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM chunks",
        [],
        |row| row.get(0),
    )?;
    Ok((count as u64, (blob_bytes + chunk_bytes) as u64))
}

pub fn current_peer_usage(conn: &Connection, target_peer: &str) -> rusqlite::Result<u64> {
    conn.query_row(
        "SELECT COALESCE(SUM(zst_size), 0) FROM pending_deltas WHERE target_peer = ?1",
        params![target_peer],
        |row| Ok(row.get::<_, i64>(0)? as u64),
    )
}

pub fn is_valid_chunk_id(chunk_id: &str) -> bool {
    (16..=128).contains(&chunk_id.len()) && chunk_id.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn release_delta_chunks(
    tx: &rusqlite::Transaction<'_>,
    delta_id: i64,
) -> rusqlite::Result<Vec<String>> {
    let mut stmt = tx.prepare("SELECT chunk_id FROM delta_chunks WHERE delta_id = ?1")?;
    let chunk_ids: Vec<String> = stmt
        .query_map(params![delta_id], |r| r.get(0))?
        .filter_map(Result::ok)
        .collect();
    drop(stmt);
    tx.execute(
        "DELETE FROM delta_chunks WHERE delta_id = ?1",
        params![delta_id],
    )?;
    let mut unreferenced = Vec::new();
    for cid in chunk_ids {
        let refs: i64 = tx.query_row(
            "SELECT COUNT(*) FROM delta_chunks WHERE chunk_id = ?1",
            params![cid],
            |r| r.get(0),
        )?;
        if refs == 0 {
            tx.execute("DELETE FROM chunks WHERE chunk_id = ?1", params![cid])?;
            unreferenced.push(cid);
        }
    }
    Ok(unreferenced)
}

pub fn is_blob_referenced(conn: &Connection, blob_name: &str) -> rusqlite::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pending_deltas WHERE blob_name = ?1",
        params![blob_name],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

pub fn user_chunks_usage(conn: &Connection) -> rusqlite::Result<(u64, u64)> {
    let (count, bytes): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM user_chunks",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok((count as u64, bytes as u64))
}

pub fn purge_user_db_rows(conn: &Connection, user_id: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM devices WHERE user_id = ?1", params![user_id])?;
    conn.execute(
        "DELETE FROM folder_manifests WHERE user_id = ?1",
        params![user_id],
    )?;
    conn.execute(
        "DELETE FROM sync_requests WHERE user_id = ?1",
        params![user_id],
    )?;
    conn.execute(
        "DELETE FROM user_chunks WHERE user_id = ?1",
        params![user_id],
    )?;
    conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
    Ok(())
}
