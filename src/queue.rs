//! The SQLite table. Times are unix milliseconds.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA_VERSION: i64 = 1;

pub(crate) struct Row {
    pub id: i64,
    pub created_ms: i64,
    pub mail_from: Option<String>,
    pub rcpt: String,
    pub data: Vec<u8>,
    pub attempts: u32,
}

pub(crate) fn open(path: &Path) -> Result<Connection, crate::Error> {
    create_private(path).map_err(|_| crate::Error::Config("cannot create the database file"))?;
    let conn = Connection::open(path)?;
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(crate::Error::Config("the database cannot use WAL"));
    }
    conn.execute_batch(
        "PRAGMA synchronous = FULL;
         PRAGMA secure_delete = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    match version {
        0 => conn.execute_batch(
            "BEGIN;
             CREATE TABLE outbox (
               id              INTEGER PRIMARY KEY,
               created_ms      INTEGER NOT NULL,
               mail_from       TEXT,
               rcpt            TEXT    NOT NULL,
               data            BLOB    NOT NULL,
               attempts        INTEGER NOT NULL DEFAULT 0,
               next_attempt_ms INTEGER NOT NULL,
               last_error      TEXT
             ) STRICT;
             CREATE INDEX outbox_due ON outbox (next_attempt_ms);
             PRAGMA user_version = 1;
             COMMIT;",
        )?,
        SCHEMA_VERSION => {}
        _ => {
            return Err(crate::Error::Config(
                "the database is from a newer rusty-mailbox",
            ));
        }
    }
    Ok(conn)
}

/// The file holds addresses and message bodies: owner-only from the start.
/// SQLite gives the -wal and -shm files the same mode.
fn create_private(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(path)?;
    // `mode` applies only on creation; an existing file is tightened here. This fails
    // with EPERM on a file someone else owns, which refuses it.
    #[cfg(unix)]
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    drop(file);
    Ok(())
}

pub(crate) fn insert(
    conn: &mut Connection,
    now: i64,
    mail_from: Option<&str>,
    rcpts: &[String],
    data: &[u8],
) -> rusqlite::Result<Vec<i64>> {
    let tx = conn.transaction()?;
    let mut ids = Vec::with_capacity(rcpts.len());
    {
        let mut stmt = tx.prepare(
            "INSERT INTO outbox (created_ms, mail_from, rcpt, data, next_attempt_ms)
             VALUES (?1, ?2, ?3, ?4, ?1)",
        )?;
        for rcpt in rcpts {
            stmt.execute(params![now, mail_from, rcpt, data])?;
            ids.push(tx.last_insert_rowid());
        }
    }
    tx.commit()?;
    Ok(ids)
}

pub(crate) fn next_due(conn: &Connection, now: i64) -> rusqlite::Result<Option<Row>> {
    conn.query_row(
        "SELECT id, created_ms, mail_from, rcpt, data, attempts FROM outbox
         WHERE next_attempt_ms <= ?1 ORDER BY next_attempt_ms, id LIMIT 1",
        [now],
        |r| {
            Ok(Row {
                id: r.get(0)?,
                created_ms: r.get(1)?,
                mail_from: r.get(2)?,
                rcpt: r.get(3)?,
                data: r.get(4)?,
                attempts: r.get(5)?,
            })
        },
    )
    .optional()
}

/// When the earliest row falls due.
pub(crate) fn next_wake(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT min(next_attempt_ms) FROM outbox", [], |r| r.get(0))
}

pub(crate) fn defer(
    conn: &Connection,
    id: i64,
    attempts: u32,
    next_attempt_ms: i64,
    error: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE outbox SET attempts = ?2, next_attempt_ms = ?3, last_error = ?4 WHERE id = ?1",
        params![id, attempts, next_attempt_ms, error],
    )
    .map(drop)
}

/// Copies the WAL into the main file and truncates the WAL to zero bytes, so the frames
/// that still hold deleted rows are gone. `false` if a reader blocked it; try again later.
pub(crate) fn truncate_wal(conn: &Connection) -> rusqlite::Result<bool> {
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    Ok(busy == 0)
}

pub(crate) fn delete(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM outbox WHERE id = ?1", [id])
        .map(drop)
}

/// The queued rows, oldest first. Never addresses or content.
pub(crate) fn pending(conn: &Connection, now: i64) -> rusqlite::Result<Vec<crate::Pending>> {
    conn.prepare("SELECT id, created_ms, attempts, last_error FROM outbox ORDER BY id")?
        .query_map([], |r| {
            Ok(crate::Pending {
                id: r.get(0)?,
                age: crate::ms_duration(now - r.get::<_, i64>(1)?),
                attempts: r.get(2)?,
                last_error: r.get(3)?,
            })
        })?
        .collect()
}
