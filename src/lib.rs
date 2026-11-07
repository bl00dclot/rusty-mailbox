#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod deliver;
mod queue;

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use lettre;
use lettre::Message;
use lettre::message::header;
use lettre::transport::smtp::authentication::Credentials;
use mail_auth::crypto::{RsaKey, Sha256};
use mail_auth::dkim::DkimSigner;
use mail_auth::headers::HeaderWriter;
use mail_auth::signer::Ready;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use tokio::sync::Notify;

/// Where mail goes.
#[derive(Debug, Clone)]
pub enum Route {
    /// Look up the recipient domain's MX hosts and deliver to port 25, in preference order.
    ///
    /// Moves to the next host only when the connection or TLS handshake fails. A null MX
    /// or a domain that does not exist is a permanent failure; a domain without MX records
    /// is tried directly. No MTA-STS or DANE.
    Mx {
        /// Transport security for every MX host. [`Tls::None`] is refused.
        tls: Tls,
    },
    /// Always deliver to one host: a smarthost, or a pinned MX.
    Host {
        /// Host name or IP address. With TLS, the certificate must be valid for this name.
        host: String,
        /// Usually 25 for an MX, 587 for a submission server.
        port: u16,
        /// Transport security. [`Tls::None`] is allowed only for a loopback host.
        tls: Tls,
        /// SMTP AUTH credentials. Only allowed with [`Tls::Required`].
        credentials: Option<Credentials>,
    },
}

/// Transport security for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    /// STARTTLS with a certificate that verifies for the host name. No TLS, no delivery.
    Required,
    /// STARTTLS with a verified certificate when the server offers it, plain text otherwise.
    Opportunistic,
    /// Plain text. Only allowed to a loopback host.
    None,
}

/// Outbox settings. Start from [`Config::new`].
#[derive(Debug, Clone)]
pub struct Config {
    route: Route,
    helo: String,
    dkim: Option<DkimSettings>,
    min_interval: Duration,
    retry_base: Duration,
    max_age: Duration,
}

#[derive(Clone)]
struct DkimSettings {
    domain: String,
    selector: String,
    private_key: String,
}

impl fmt::Debug for DkimSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkimSettings")
            .field("domain", &self.domain)
            .field("selector", &self.selector)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// `helo` is the name sent in `EHLO`; for direct sending it must be the host's
    /// forward-confirmed reverse DNS name.
    pub fn new(route: Route, helo: impl Into<String>) -> Self {
        Config {
            route,
            helo: helo.into(),
            dkim: None,
            min_interval: Duration::ZERO,
            retry_base: Duration::from_secs(60),
            max_age: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }

    /// Sign every message with DKIM (`rsa-sha256`) for `d=domain`, `s=selector`.
    ///
    /// `private_key` is an RSA key in PEM, PKCS#1 (`BEGIN RSA PRIVATE KEY`) or PKCS#8
    /// (`BEGIN PRIVATE KEY`). It is parsed by [`Outbox::open`].
    // ponytail: RSA only. mail-auth also signs Ed25519 (RFC 8463); add an algorithm
    // argument when a receiver that matters verifies it.
    pub fn dkim(
        mut self,
        domain: impl Into<String>,
        selector: impl Into<String>,
        private_key: impl Into<String>,
    ) -> Self {
        self.dkim = Some(DkimSettings {
            domain: domain.into(),
            selector: selector.into(),
            private_key: private_key.into(),
        });
        self
    }

    /// Least time between two delivery attempts. Default 0.
    pub fn min_interval(mut self, d: Duration) -> Self {
        self.min_interval = d;
        self
    }

    /// First retry delay; it doubles per attempt, capped at 2 hours. Default 60 s.
    pub fn retry_base(mut self, d: Duration) -> Self {
        self.retry_base = d;
        self
    }

    /// A message still undelivered this long after enqueue is dropped. Default 7 days.
    pub fn max_age(mut self, d: Duration) -> Self {
        self.max_age = d;
        self
    }
}

/// What happened to one row after a delivery attempt.
///
/// Carries no addresses or content. `id` is a row id returned by [`Outbox::enqueue`];
/// `error` is lettre's description of the failure, with every word containing `@`
/// replaced by `[address]`, cut at 500 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The server accepted the message (2xx). The row is deleted.
    Delivered {
        /// The row id.
        id: i64,
    },
    /// A transient failure (4xx, no connection, TLS or DNS failure). The row stays and
    /// is retried after the backoff.
    Deferred {
        /// The row id.
        id: i64,
        /// Failed attempts so far, including this one.
        attempts: u32,
        /// Why it failed.
        error: String,
    },
    /// A permanent failure (5xx, a null MX, a domain that does not exist, or a stored
    /// address that no longer parses). The row is deleted.
    Failed {
        /// The row id.
        id: i64,
        /// Why it failed.
        error: String,
    },
    /// A transient failure at or after `max_age`. The row is deleted.
    Expired {
        /// The row id.
        id: i64,
        /// Why the last attempt failed.
        error: String,
    },
}

/// A queued row, without its addresses or content. See [`Outbox::pending`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The row id returned by [`Outbox::enqueue`].
    pub id: i64,
    /// Time since the message was enqueued.
    pub age: Duration,
    /// Failed attempts so far.
    pub attempts: u32,
    /// The error of the last failed attempt, redacted like [`Event`] errors.
    pub last_error: Option<String>,
}

/// Why the outbox could not open, store or read. Delivery failures are never an
/// `Error`; they arrive as [`Event`]s.
#[derive(Debug)]
pub enum Error {
    /// The SQLite database failed.
    Db(rusqlite::Error),
    /// The DKIM key did not parse (`open`), or signing failed (`enqueue`).
    Dkim(String),
    /// The configuration is unsafe or the database is from a newer version.
    Config(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "outbox database: {e}"),
            Error::Dkim(e) => write!(f, "DKIM key: {e}"),
            Error::Config(e) => write!(f, "outbox config: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}

/// A durable SQLite outbox with a background SMTP delivery loop.
///
/// Share it with `Arc<Outbox>`: call [`Outbox::enqueue`] from anywhere and run
/// [`Outbox::run`] once. Run one loop per database file; two loops on the same file
/// would send rows twice.
pub struct Outbox {
    db: Mutex<rusqlite::Connection>,
    wake: Notify,
    config: Config,
    dkim: Option<DkimSigner<RsaKey<Sha256>, Ready>>,
}

impl Outbox {
    /// Opens or creates the database at `path` and checks `config`.
    ///
    /// Fails with [`Error::Config`] for an unsafe route (plain text to a host that is not
    /// loopback, credentials without [`Tls::Required`]), or a database from a newer
    /// version, and with [`Error::Dkim`] if the DKIM key does not parse. The file is
    /// created mode `0600`.
    pub fn open(path: impl AsRef<Path>, mut config: Config) -> Result<Self, Error> {
        check_route(&config.route)?;
        // The signer holds the parsed key; the PEM text is not kept.
        let dkim = config.dkim.take().as_ref().map(signer).transpose()?;
        let db = queue::open(path.as_ref())?;
        Ok(Outbox {
            db: Mutex::new(db),
            wake: Notify::new(),
            config,
            dkim,
        })
    }

    /// Signs `message`, stores one row per envelope recipient and wakes the loop.
    ///
    /// When this returns `Ok`, the rows are on disk (WAL, `synchronous=FULL`). Returns
    /// one row id per distinct recipient. Any `Bcc:` header is removed first. On `Err`
    /// (a database or signing failure) nothing was stored. This blocks on a disk sync: from async code, call it through
    /// `tokio::task::spawn_blocking`.
    pub fn enqueue(&self, mut message: Message) -> Result<Vec<i64>, Error> {
        // lettre already drops Bcc unless the builder asked to keep it.
        message.headers_mut().remove::<header::Bcc>();
        let envelope = message.envelope();
        let from = envelope.from().map(ToString::to_string);
        let mut rcpts: Vec<String> = envelope.to().iter().map(ToString::to_string).collect();
        rcpts.sort();
        rcpts.dedup();
        let mut data = message.formatted();
        if let Some(dkim) = &self.dkim {
            let signature = dkim.sign(&data).map_err(|e| Error::Dkim(e.to_string()))?;
            let mut signed = signature.to_header().into_bytes();
            signed.append(&mut data);
            data = signed;
        }
        let ids = queue::insert(&mut self.db(), now_ms(), from.as_deref(), &rcpts, &data)?;
        self.wake.notify_one();
        Ok(ids)
    }

    /// The rows still waiting, oldest first. Never addresses or content.
    pub fn pending(&self) -> Result<Vec<Pending>, Error> {
        Ok(queue::pending(&self.db(), now_ms())?)
    }

    /// Delivers rows until `shutdown` resolves, calling `on_event` after each attempt.
    ///
    /// One attempt at a time, at least `min_interval` apart. An attempt still in
    /// progress when `shutdown` resolves is abandoned and repeated later, so delivery is
    /// at least once. Returns `Err` only on a database error; treat it as fatal.
    pub async fn run<F: FnMut(Event)>(
        &self,
        shutdown: impl Future<Output = ()>,
        mut on_event: F,
    ) -> Result<(), Error> {
        tokio::pin!(shutdown);
        let mut resolver = None;
        let mut last_attempt: Option<Instant> = None;
        // A row was deleted since the WAL was last truncated.
        let mut residue = true;
        loop {
            let now = now_ms();
            let due = queue::next_due(&self.db(), now)?;
            let Some(row) = due else {
                // Idle: nothing is due. Deleted rows still sit in WAL frames, so move the
                // WAL into the main file (where secure_delete has zeroed them) and truncate
                // it. Under load the loop is never idle, so this costs nothing there.
                if residue {
                    residue = !queue::truncate_wal(&self.db())?;
                }
                // Also wake once a minute, in case the wall clock jumped.
                let next = queue::next_wake(&self.db())?;
                let wait = next.map_or(IDLE_WAKE, |t| ms_duration(t - now).min(IDLE_WAKE));
                tokio::select! {
                    biased;
                    () = &mut shutdown => return Ok(()),
                    () = self.wake.notified() => {}
                    () = tokio::time::sleep(wait) => {}
                }
                continue;
            };
            // ponytail: one delivery at a time, min_interval apart, from one loop. Fine for low
            // volume and per-host sending caps; parallel per-domain workers if a
            // backlog ever has to drain fast.
            if let Some(last) = last_attempt {
                tokio::select! {
                    biased;
                    () = &mut shutdown => return Ok(()),
                    () = tokio::time::sleep_until((last + self.config.min_interval).into()) => {}
                }
            }
            // Shutdown mid-transaction leaves the row; it is sent again later (at least once).
            let outcome = tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                o = deliver::attempt(&self.config, &mut resolver, &row) => o,
            };
            last_attempt = Some(Instant::now());
            let event = self.settle(&row, outcome)?;
            residue |= !matches!(event, Event::Deferred { .. });
            on_event(event);
        }
    }

    /// Deletes or reschedules `row` after an attempt.
    fn settle(&self, row: &queue::Row, outcome: deliver::Outcome) -> Result<Event, Error> {
        let db = self.db();
        let id = row.id;
        Ok(match outcome {
            deliver::Outcome::Delivered => {
                queue::delete(&db, id)?;
                Event::Delivered { id }
            }
            deliver::Outcome::Permanent(error) => {
                queue::delete(&db, id)?;
                Event::Failed { id, error }
            }
            deliver::Outcome::Transient(error) => {
                let now = now_ms();
                let deadline = row
                    .created_ms
                    .saturating_add(duration_ms(self.config.max_age));
                if now >= deadline {
                    queue::delete(&db, id)?;
                    return Ok(Event::Expired { id, error });
                }
                let attempts = row.attempts + 1;
                let delay = duration_ms(deliver::backoff(self.config.retry_base, attempts));
                // The last try lands on the deadline, so no row outlives max_age by a backoff.
                let next = now.saturating_add(delay).min(deadline);
                queue::defer(&db, id, attempts, next, &error)?;
                Event::Deferred {
                    id,
                    attempts,
                    error,
                }
            }
        })
    }

    fn db(&self) -> MutexGuard<'_, rusqlite::Connection> {
        // A panic elsewhere cannot leave SQLite half-written; keep going.
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Every header that a receiver shows or acts on, each named twice. mail-auth signs every
/// instance present and adds one empty `h=` entry for each name it did not match, so the
/// second name over-signs: a header added in transit, absent or present, breaks the
/// signature.
const SIGNED_HEADERS: [&str; 20] = [
    "From",
    "From",
    "To",
    "To",
    "Cc",
    "Cc",
    "Subject",
    "Subject",
    "Date",
    "Date",
    "Message-ID",
    "Message-ID",
    "Reply-To",
    "Reply-To",
    "MIME-Version",
    "MIME-Version",
    "Content-Type",
    "Content-Type",
    "Content-Transfer-Encoding",
    "Content-Transfer-Encoding",
];

const IDLE_WAKE: Duration = Duration::from_secs(60);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_ms)
}

fn duration_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

fn ms_duration(ms: i64) -> Duration {
    Duration::from_millis(u64::try_from(ms).unwrap_or(0))
}

fn signer(d: &DkimSettings) -> Result<DkimSigner<RsaKey<Sha256>, Ready>, Error> {
    let der = PrivateKeyDer::from_pem_slice(d.private_key.as_bytes())
        .map_err(|e| Error::Dkim(e.to_string()))?;
    let key = RsaKey::<Sha256>::from_key_der(der).map_err(|e| Error::Dkim(e.to_string()))?;
    Ok(DkimSigner::from_key(key)
        .domain(d.domain.clone())
        .selector(d.selector.clone())
        .headers(SIGNED_HEADERS))
}

fn check_route(route: &Route) -> Result<(), Error> {
    match route {
        Route::Mx { tls: Tls::None } => Err(Error::Config("Tls::None is only for loopback hosts")),
        Route::Mx { .. } => Ok(()),
        Route::Host {
            host,
            tls,
            credentials,
            ..
        } => {
            if *tls == Tls::None && !is_loopback(host) {
                return Err(Error::Config("Tls::None is only for loopback hosts"));
            }
            if credentials.is_some() && *tls != Tls::Required {
                return Err(Error::Config("credentials need Tls::Required"));
            }
            Ok(())
        }
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
