use std::path::Path;

use rusqlite::{params, Connection};

pub fn init_db(db_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
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
            device_id TEXT NOT NULL,
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
        CREATE TABLE IF NOT EXISTS shares (
            user_id TEXT NOT NULL,
            share_id TEXT NOT NULL,
            owner_device_id TEXT NOT NULL,
            last_writer_device_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            encrypted_manifest_b64 TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY (user_id, share_id)
        );
        CREATE TABLE IF NOT EXISTS user_chunks (
            user_id TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            last_accessed_ms INTEGER NOT NULL,
            PRIMARY KEY (user_id, chunk_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_chunks_lru ON user_chunks(last_accessed_ms);
        CREATE TABLE IF NOT EXISTS reseed_requests (
            user_id TEXT NOT NULL,
            share_id TEXT NOT NULL,
            chunk_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (user_id, share_id, chunk_id)
        );
        ",
    )?;
    Ok(conn)
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
    conn.execute("DELETE FROM shares WHERE user_id = ?1", params![user_id])?;
    conn.execute(
        "DELETE FROM user_chunks WHERE user_id = ?1",
        params![user_id],
    )?;
    conn.execute(
        "DELETE FROM reseed_requests WHERE user_id = ?1",
        params![user_id],
    )?;
    conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
    Ok(())
}
