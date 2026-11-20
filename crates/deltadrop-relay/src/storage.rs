use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use tracing::info;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub struct QuotaGuard {
    pub counter: Arc<AtomicU64>,
    pub amount: u64,
}

impl Drop for QuotaGuard {
    fn drop(&mut self) {
        if self.amount > 0 {
            self.counter.fetch_sub(self.amount, Ordering::SeqCst);
        }
    }
}

pub fn gc_expired_deltas(db: &Mutex<Connection>, blobs_dir: &Path, ttl_secs: u64) -> usize {
    if ttl_secs == 0 {
        return 0;
    }
    let cutoff = now_ms().saturating_sub((ttl_secs as i64) * 1000);
    let expired: Vec<(i64, String)> = {
        let Ok(conn) = db.lock() else {
            return 0;
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT id, blob_name FROM pending_deltas WHERE created_at_ms < ?1")
        else {
            return 0;
        };
        let Ok(rows) = stmt.query_map(params![cutoff], |r| Ok((r.get(0)?, r.get(1)?))) else {
            return 0;
        };
        let items: Vec<(i64, String)> = rows.filter_map(Result::ok).collect();
        drop(stmt);
        let _ = conn.execute(
            "DELETE FROM pending_deltas WHERE created_at_ms < ?1",
            params![cutoff],
        );
        let _ = conn.execute(
            "DELETE FROM pull_requests WHERE created_at_ms < ?1",
            params![cutoff],
        );
        items
    };
    let count = expired.len();
    for (_, blob) in expired {
        if !blob.is_empty() {
            let _ = std::fs::remove_file(blobs_dir.join(blob));
        }
    }
    if count > 0 {
        info!("Expired {count} stale relay delta(s) older than {ttl_secs}s");
    }
    count
}

pub fn gc_orphan_blobs(db: &Mutex<Connection>, blobs_dir: &Path, min_age_secs: u64) -> usize {
    let active: HashSet<String> = {
        let Ok(conn) = db.lock() else {
            return 0;
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT blob_name FROM pending_deltas WHERE blob_name != ''")
        else {
            return 0;
        };
        let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) else {
            return 0;
        };
        rows.filter_map(Result::ok).collect()
    };

    let Ok(entries) = std::fs::read_dir(blobs_dir) else {
        return 0;
    };
    let mut removed = 0usize;
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if active.contains(&name) {
            continue;
        }
        if min_age_secs > 0 {
            let age_ok = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .map(|d| d >= Duration::from_secs(min_age_secs))
                .unwrap_or(false);
            if !age_ok {
                continue;
            }
        }
        if std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        info!("Garbage-collected {removed} orphaned relay blob(s)");
    }
    removed
}

pub fn gc_expired_user_chunks(db: &Mutex<Connection>, chunks_dir: &Path, ttl_secs: u64) -> usize {
    if ttl_secs == 0 {
        return 0;
    }
    let cutoff = now_ms().saturating_sub((ttl_secs as i64) * 1000);
    let expired: Vec<(String, String)> = {
        let Ok(conn) = db.lock() else {
            return 0;
        };
        let Ok(mut stmt) =
            conn.prepare("SELECT user_id, chunk_id FROM user_chunks WHERE created_at_ms < ?1")
        else {
            return 0;
        };
        let Ok(rows) = stmt.query_map(params![cutoff], |r| Ok((r.get(0)?, r.get(1)?))) else {
            return 0;
        };
        let items: Vec<(String, String)> = rows.filter_map(Result::ok).collect();
        drop(stmt);
        let _ = conn.execute(
            "DELETE FROM user_chunks WHERE created_at_ms < ?1",
            params![cutoff],
        );
        let _ = conn.execute(
            "DELETE FROM sessions WHERE expires_at_ms < ?1",
            params![now_ms()],
        );
        items
    };
    let count = expired.len();
    for (user_id, chunk_id) in expired {
        let _ = std::fs::remove_file(chunks_dir.join(user_id).join(format!("{chunk_id}.chk")));
    }
    if count > 0 {
        info!("Expired {count} TTL user chunk(s) older than {ttl_secs}s");
    }
    count
}

pub fn evict_lru_user_chunks(db: &Mutex<Connection>, chunks_dir: &Path, max_bytes: u64) -> usize {
    if max_bytes == 0 {
        return 0;
    }
    let to_evict: Vec<(String, String)> = {
        let Ok(conn) = db.lock() else {
            return 0;
        };
        let total: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM user_chunks",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if (total as u64) <= max_bytes {
            return 0;
        }
        let mut excess = (total as u64).saturating_sub(max_bytes);
        let Ok(mut stmt) = conn.prepare(
            "SELECT user_id, chunk_id, size_bytes FROM user_chunks ORDER BY last_accessed_ms ASC",
        ) else {
            return 0;
        };
        let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? as u64,
            ))
        }) else {
            return 0;
        };
        let mut victims = Vec::new();
        for row in rows.flatten() {
            if excess == 0 {
                break;
            }
            excess = excess.saturating_sub(row.2);
            victims.push((row.0, row.1));
        }
        drop(stmt);
        for (uid, cid) in &victims {
            let _ = conn.execute(
                "DELETE FROM user_chunks WHERE user_id = ?1 AND chunk_id = ?2",
                params![uid, cid],
            );
        }
        victims
    };
    let count = to_evict.len();
    for (uid, cid) in to_evict {
        let _ = std::fs::remove_file(chunks_dir.join(uid).join(format!("{cid}.chk")));
    }
    if count > 0 {
        info!("LRU-evicted {count} user chunk(s) to stay under max_bytes={max_bytes}");
    }
    count
}
