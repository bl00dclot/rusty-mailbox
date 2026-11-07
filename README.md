# rusty-mailbox

A durable outbox for sending mail from a Rust service. Hand it a [`lettre::Message`]. It writes the message to SQLite before returning, then delivers it in the background over SMTP, with STARTTLS, optional DKIM signing, retries with backoff, and pacing.

Use it when a service has to send mail and must not lose it: a contact form, sign-up confirmations, alerts. It is one library with no daemon to run and no second queue to look after. Delivery is **at least once**, and a message's content is deleted the moment it is delivered, fails permanently or expires.

It is not a mail server. It does not receive mail, process bounces, or send bulk mail fast.

How it is built (modules, schema, the delivery loop, error classification, tests) is in `docs/ARCHITECTURE.md` in the repository.

## Contents

1. Installing
2. Quick start
3. Configuration
4. Routes and TLS
5. DKIM
6. Events
7. Monitoring
8. Running it in a service
9. Guarantees
10. Errors
11. Privacy and security
12. Sending straight to the recipient's MX: DNS checklist
13. Limits
14. Compatibility
15. Development
16. License

## Installing

The crate is not on crates.io. Depend on the git repository and pin a tag:

```toml
[dependencies]
rusty-mailbox = { git = "https://github.com/bl00dclot/rusty-mailbox", tag = "v0.1.0" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
```

Build messages with the re-exported lettre, `rusty_mailbox::lettre`, so your lettre and the outbox's lettre are always the same version. If you also depend on lettre directly, pin exactly the version in this crate's `Cargo.lock`.

The delivery loop needs a Tokio runtime. TLS is rustls with the Mozilla root certificates built in (webpki-roots), so the host needs no OpenSSL and no system certificate store. TLS and DKIM both use AWS-LC as the cryptography library, which builds from C sources: the build machine needs a C compiler (`gcc` or `clang`; for musl targets, `musl-tools`). CMake, Go and bindgen are not needed.

**Build AWS-LC once.** mail-auth links `aws-lc-sys` directly, and so does `aws-lc-rs`, which rustls and mail-auth use. When their versions drift apart, Cargo builds two copies of AWS-LC: a slower build and a bigger binary. Check your application with `cargo tree -d -e normal | grep aws-lc-sys`. If it lists two versions, pin `aws-lc-rs` to the release that uses mail-auth's `aws-lc-sys`, for example `cargo update -p aws-lc-rs --precise 1.18.2` for mail-auth 0.15.1. This crate's own CI (cargo-deny) fails on a duplicate.

## Quick start

```rust,no_run
use std::sync::Arc;

use rusty_mailbox::lettre::Message;
use rusty_mailbox::{Config, Event, Outbox, Route, Tls};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = std::fs::read_to_string("/run/credentials/app.service/dkim-key")?;
    let config = Config::new(
        Route::Host {
            host: "mx.example.net".into(),
            port: 25,
            tls: Tls::Required,
            credentials: None,
        },
        "mail.example.com", // forward-confirmed reverse DNS name of this host
    )
    .dkim("mail.example.com", "s1", key)
    .min_interval(std::time::Duration::from_secs(15));

    let outbox = Arc::new(Outbox::open("/var/lib/app/outbox.sqlite3", config)?);

    let worker = outbox.clone();
    let delivery = tokio::spawn(async move {
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        worker
            .run(shutdown, |event| match event {
                Event::Delivered { id } => eprintln!("mail {id} delivered"),
                Event::Deferred { id, attempts, error } => {
                    eprintln!("mail {id} deferred (attempt {attempts}): {error}")
                }
                Event::Failed { id, error } => eprintln!("mail {id} failed: {error}"),
                Event::Expired { id, error } => eprintln!("mail {id} expired: {error}"),
            })
            .await
    });

    let message = Message::builder()
        .from("App <noreply@mail.example.com>".parse()?)
        .reply_to("support@example.com".parse()?)
        .to("someone@example.net".parse()?)
        .subject("Hello")
        .body(String::from("Hello"))?;
    let ids = outbox.enqueue(message)?; // on disk once this returns
    eprintln!("queued {ids:?}");

    delivery.await??; // runs until Ctrl-C
    Ok(())
}
```

There are three steps:

1. `Outbox::open` checks the configuration, parses the DKIM key, and creates or migrates the database.
2. `Outbox::run` is the delivery loop. Start it once, in its own task, and keep it running.
3. `Outbox::enqueue` signs and stores a message and wakes the loop. Call it from anywhere, as often as you like.

## Configuration

Start from `Config::new(route, helo)` and chain the setters you need:

| Setting | Default | Meaning |
| --- | --- | --- |
| `route` (required) | | Where mail goes. See "Routes and TLS". |
| `helo` (required) | | The name sent in `EHLO`. For direct sending it must be the host's forward-confirmed reverse DNS name; receivers check it. |
| `.dkim(domain, selector, pem)` | off | Sign every message with `d=domain`, `s=selector`. See "DKIM". |
| `.min_interval(d)` | 0 | The least time between the end of one delivery attempt and the start of the next. Set it under your host's or relay's sending cap: 15 s keeps under 5 a minute. |
| `.retry_base(d)` | 60 s | The first retry delay after a transient failure. It doubles with each attempt, capped at 2 hours: 60 s, 2 min, 4 min, … 64 min, then every 2 h. |
| `.max_age(d)` | 7 days | A message that is still undelivered this long after `enqueue` is deleted, and `Expired` fires. |

`Outbox::open` refuses an unsafe configuration at start-up rather than at the first send:

| Configuration | Result |
| --- | --- |
| `Tls::None` to a host that is not loopback (`127.0.0.0/8`, `::1`, `localhost`) | `Error::Config` |
| `Route::Mx { tls: Tls::None }` | `Error::Config` |
| Credentials with `Tls::Opportunistic` or `Tls::None` | `Error::Config` |
| A database written by a newer rusty-mailbox | `Error::Config` |
| A DKIM key that does not parse | `Error::Dkim` |

## Routes and TLS

`Route` says where each message goes; `Tls` says how the connection is protected.

| `Tls` | Behaviour |
| --- | --- |
| `Required` | STARTTLS, and the certificate must verify for the host name against the Mozilla roots. Without it nothing is sent, and the attempt is a transient failure. The one to choose. |
| `Opportunistic` | STARTTLS if the server offers it, plain text if it does not. A certificate that is offered must still verify. An on-path attacker can strip the offer and read the mail. |
| `None` | Plain text. Only for a relay on loopback. |

There is no setting that skips certificate verification. A server with a certificate that does not match its name cannot be reached.

**A smarthost** (your provider's submission server):

```rust,no_run
# use rusty_mailbox::{Route, Tls};
# use rusty_mailbox::lettre::transport::smtp::authentication::Credentials;
let route = Route::Host {
    host: "smtp.example.net".into(),
    port: 587,
    tls: Tls::Required,
    credentials: Some(Credentials::new("user".into(), "password".into())),
};
```

**A pinned MX.** Every message goes to one known receiving server, for example your own mailbox provider's MX. Pinning the host is how you honour a domain's MTA-STS `mx` without implementing MTA-STS.

```rust,no_run
# use rusty_mailbox::{Route, Tls};
let route = Route::Host {
    host: "mx.example.net".into(),
    port: 25,
    tls: Tls::Required,
    credentials: None,
};
```

**Any domain, through DNS:**

```rust,no_run
# use rusty_mailbox::{Route, Tls};
let route = Route::Mx { tls: Tls::Required };
```

- The recipient domain's MX hosts are tried in preference order, on port 25.
- The loop moves to the next host only when the connection or the TLS handshake fails. Any SMTP reply, good or bad, settles the attempt.
- A null MX (RFC 7505) and a domain that does not exist are permanent failures. A domain with no MX records is tried directly, as RFC 5321 says.
- **No MTA-STS or DANE yet.** DNS decides which host gets the mail, and an attacker who can spoof DNS answers can pick it. `Tls::Required` still demands a valid certificate for whatever host DNS named.

**A local relay:**

```rust,no_run
# use rusty_mailbox::{Route, Tls};
let route = Route::Host { host: "127.0.0.1".into(), port: 25, tls: Tls::None, credentials: None };
```

## DKIM

```rust,no_run
# use rusty_mailbox::{Config, Route, Tls};
# let route = Route::Mx { tls: Tls::Required };
let pem = std::fs::read_to_string("/run/credentials/app.service/dkim-key")?;
let config = Config::new(route, "mail.example.com").dkim("mail.example.com", "s1", pem);
# Ok::<(), std::io::Error>(())
```

- **The key** is an RSA key in PEM, either PKCS#1 (`BEGIN RSA PRIVATE KEY`, from `openssl genrsa -traditional 2048`) or PKCS#8 (`BEGIN PRIVATE KEY`, what `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` writes). Use 2048 bits. A key that does not parse fails `open` with `Error::Dkim`.
- **Signing happens once, at `enqueue`.** The stored bytes are exactly the bytes sent, on every retry.
- **What is signed:** the body, and the headers `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `Reply-To`, `MIME-Version`, `Content-Type` and `Content-Transfer-Encoding`. A header in that list that the message does not have is signed as absent, so it cannot be added on the way either. `rsa-sha256`, `relaxed/relaxed` canonicalization.
- **RSA only** for now. Ed25519 (RFC 8463) is not offered, because many receivers still ignore Ed25519 signatures.
- **Rotating the key:** publish the new selector, restart with the new key and selector, and keep the old selector's DNS record until `max_age` has passed. Rows already queued carry signatures made with the old key.

### Why mail-auth on AWS-LC, not lettre's DKIM

lettre's `dkim` feature signs with the pure-Rust `rsa` crate, which is affected by RUSTSEC-2023-0071 (the Marvin attack): its modular exponentiation is not constant time, so the time a signature takes leaks information about the private key. No fixed release exists. Here a signature is made at `enqueue`, often inside a web request whose response time an outsider can measure.

This crate signs with [mail-auth](https://crates.io/crates/mail-auth) on [AWS-LC](https://github.com/aws/aws-lc), Amazon's fork of Google's BoringSSL. The Marvin authors tested BoringSSL as not vulnerable; AWS-LC is not on their list, but keeps BoringSSL's RSA implementation lineage and is maintained by a security team. The `rsa` crate and `ring` are not in the dependency tree at all, and CI checks that they stay out.

## Events

`run` calls your `on_event` once after every delivery attempt:

| Event | When | Row |
| --- | --- | --- |
| `Delivered { id }` | The server accepted the message (2xx after `DATA`) | deleted |
| `Deferred { id, attempts, error }` | A transient failure: a 4xx reply, no connection, a TLS failure, a DNS failure | kept; retried after the backoff |
| `Failed { id, error }` | A permanent failure: a 5xx reply, a null MX, a domain that does not exist, a stored address that no longer parses | deleted |
| `Expired { id, error }` | A transient failure at or after `max_age` | deleted |

- `id` is the row id that `enqueue` returned for that recipient.
- `error` is the server's reply when there was one, such as `transient error (451): 4.7.1 try again later`; any word containing `@` is replaced by `[address]`, and the text is cut at 500 characters. Without a reply it is one of the fixed strings `connection failed`, `TLS failure`, `timed out` or `bad SMTP reply`, or a fixed DNS string, because the underlying error can name the recipient's mail host or domain.
- `on_event` runs inside the delivery loop, so keep it short: log, count, or hand off to a channel.
- `Failed` and `Expired` are final: the content is gone. If someone has to know, alert from these two events.

## Monitoring

`pending()` lists the rows still waiting, oldest first, with no addresses or content:

```rust,no_run
# use std::time::Duration;
# async fn watch(outbox: std::sync::Arc<rusty_mailbox::Outbox>) -> Result<(), rusty_mailbox::Error> {
let mut tick = tokio::time::interval(Duration::from_secs(60));
loop {
    tick.tick().await;
    for p in outbox.pending()? {
        if p.age > Duration::from_secs(3600) {
            eprintln!("mail {} stuck for {:?}, {} attempts: {:?}", p.id, p.age, p.attempts, p.last_error);
        }
    }
}
# }
```

`Pending` has `id`, `age`, `attempts` and `last_error` (the error of the last `Deferred`).

If you send alerts through the same outbox, an alert can itself be deferred or fail. Do not alert on an alert's own row, and cap how often you alert. An alert sent through the outbox also cannot reach anyone while the outbox's own route is down; only something outside the process can notice that.

## Running it in a service

- **Share one `Outbox`.** Put it in an `Arc`. `Outbox` is `Send + Sync`; `enqueue` and `pending` take `&self`.
- **Run one loop per database.** Run `run` once per process, and use one process per database file. Two loops on the same file would send the same row twice. Nothing in the crate prevents this; your process manager has to, for example with a single systemd unit.
- **`enqueue` blocks.** It writes to SQLite and waits for the disk to sync, which usually takes milliseconds but can take longer on slow storage. From async code, call it through `spawn_blocking`:

  ```rust,no_run
  # use std::sync::Arc;
  # use rusty_mailbox::{Outbox, lettre::Message};
  async fn send(
      outbox: Arc<Outbox>,
      message: Message,
  ) -> Result<Vec<i64>, Box<dyn std::error::Error + Send + Sync>> {
      Ok(tokio::task::spawn_blocking(move || outbox.enqueue(message)).await??)
  }
  ```

  Tell the user the message is sent only once `enqueue` returned `Ok`. On `Err` nothing was stored, so tell them it failed.
- **Shutdown.** `run` returns `Ok(())` when the `shutdown` future resolves. An attempt in progress at that moment is abandoned, and the row is sent again after the restart. Messages enqueued while the loop is stopped wait on disk.
- **Database errors.** `run` returns `Err` only on a database error. Treat it as fatal: exit and let the process manager restart you.

A systemd unit that fits:

```ini
[Service]
ExecStart=/usr/local/bin/app
DynamicUser=yes
# The outbox goes at $STATE_DIRECTORY/outbox.sqlite3
StateDirectory=app
# Read the key from $CREDENTIALS_DIRECTORY/dkim-key
LoadCredential=dkim-key:/etc/credstore/app.dkim-key
Restart=on-failure
```

`open` sets the database file to mode `0600`, so only the service user can read the queued mail.

## Guarantees

- **Durable.** The database runs in WAL mode with `synchronous=FULL`. When `enqueue` returns `Ok`, the message survives a crash or power cut.
- **At least once.** If the server accepts a message but its final `250` is lost, or the process stops mid-transaction, the message is sent again. A rare duplicate is the price.
- **Nothing outlives delivery.** A row is deleted the moment its mail is delivered (2xx), fails permanently (5xx, null MX, a domain that does not exist) or expires (`max_age`, default 7 days).
  - **Deleted means gone from every file.** `secure_delete` zeroes deleted rows in the main file. Each time the delivery loop goes idle after a deletion, it copies the write-ahead log into the main file and truncates the log to zero bytes (`wal_checkpoint(TRUNCATE)`). From then on the message is in none of the three files: `.sqlite3`, `-wal` and `-shm`. A test reads the bytes of all three to check this.
  - **Until then,** during a backlog or if the process stops first, the `-wal` file can still hold recently deleted rows. The next idle moment after a restart clears them.
  - **Below the file level,** disk blocks freed by the truncation keep their old bytes until the file system reuses them, and a block-level backup or disk image can capture them. Use an encrypted disk if that matters.
  - `open` sets the file to mode `0600`, whether it creates it or finds it.
- **One row per envelope recipient.** `To`, `Cc` and `Bcc` each get their own transaction, so one bad address never blocks the others, and the `Bcc:` header is removed before signing and storing.
- **Transport security by default.** `Tls::Required` means STARTTLS with a certificate verified against the Mozilla roots for the host name. `Tls::None` is refused for any host that is not loopback, and credentials are refused without `Tls::Required`.
- **Retries.** Transient failures (4xx, no connection, TLS failure) back off from `retry_base` (default 60 s), doubling, capped at 2 hours. The last try lands on the `max_age` deadline.
- **Pacing.** One delivery at a time, at least `min_interval` apart (default 0). Set it under your host's sending cap.
- **No personal data in the output.** The crate does not log. `Event` and `pending()` carry row ids, ages, attempt counts and the server's reply, with any word containing `@` replaced by `[address]`; errors without a reply are fixed strings. A server may still quote other text in its reply, including a recipient's name; treat `error` as operational data.

## Errors

| Variant | Returned by | Meaning |
| --- | --- | --- |
| `Error::Config(&'static str)` | `open` | The configuration is unsafe, the database file cannot be created, the file system cannot do WAL, or the database is from a newer version. The text says which. |
| `Error::Dkim(String)` | `open`, `enqueue` | The DKIM key did not parse (`open`), or a message could not be signed (`enqueue`; nothing was stored). |
| `Error::Db(rusqlite::Error)` | `open`, `enqueue`, `pending`, `run` | SQLite failed: a full disk, a corrupt file, a permission error. |

Delivery failures are never an `Error`. They arrive as `Event`s.

## Privacy and security

- **No logging.** The crate logs nothing. Everything it reports goes through `Event` and `pending()`, and neither carries an address or message content.
- **Redaction.** Server replies often quote the recipient (`550 5.1.1 <user@example.net>: no such user`), so every word containing `@` becomes `[address]`. This is best effort: a reply can still identify the recipient without an `@` (`550 jdoe unavailable`), and a quoted local part containing a space (`"j doe"@example.net`) is only partly masked. Connection, TLS and DNS errors are reduced to fixed strings, because they would name the recipient's mail host or domain.
- **File mode.** `open` sets the database file to `0600`, whether it creates it or finds it, and refuses a file it cannot change (one owned by another user).
- **At rest.** The database holds full messages and addresses until each row is deleted. It is created mode `0600`. Deleted rows are zeroed in the main file, and the write-ahead log is truncated whenever the loop goes idle (see Guarantees). Put the database on an encrypted disk if the host's storage, or its block-level backups, are not trusted.
- **Headers.** Build messages with lettre's typed builder, never by pasting user input into raw headers. lettre encodes header values, which prevents header injection.
- **Bcc.** The `Bcc:` header is removed even if the builder asked lettre to keep it. Each Bcc recipient gets its own transaction.
- **Certificates.** Every TLS connection verifies the server certificate for the host name.
- **Credentials** are sent only over `Tls::Required`, enforced at `open`.

## Sending straight to the recipient's MX: DNS checklist

Receiving servers judge a VPS harshly. Before the first message:

- **Port 25 open.** Many hosts and cloud providers block outbound port 25, or allow it only on request. Test with `nc -vz <mx-host> 25` from the server.
- **Forward-confirmed reverse DNS.** The IP's PTR names a host that resolves back to the same IP, and that name is the `helo` you pass to `Config::new`.
- **SPF** on the `From` domain (best a dedicated subdomain): `v=spf1 ip4:<ipv4> ip6:<ipv6> -all`.
- **DKIM key.** An RSA key in PEM (PKCS#1 or PKCS#8):
  ```sh
  (umask 077; openssl genrsa -traditional -out dkim-key.pem 2048)
  openssl rsa -in dkim-key.pem -pubout -outform DER | base64 -w0; echo
  ```
  Publish the second line as `<selector>._domainkey.<domain> TXT "v=DKIM1; k=rsa; p=<key>"`.
- **DMARC alignment.** The DKIM `d=` and the SPF envelope domain must match the `From` domain (exactly, under `adkim=s`/`aspf=s`). Signing with `Config::dkim` for the `From` domain gives that.
- **Blocklists.** Check the IP against Spamhaus ZEN and the other major lists before relying on it.

A dedicated sending subdomain (`mail.example.com` rather than `example.com`) keeps the sending reputation, and the reach of a leaked DKIM key, away from the domain people write to.

## Limits

- **`Route::Mx` is experimental in 0.1.** It has no MTA-STS or DANE, so DNS decides which host receives the mail. It also connects to whatever address an MX resolves to, including loopback and private addresses: if recipient domains come from untrusted input, a crafted domain can point delivery at an internal host. Pin the host with `Route::Host` where either matters.
- **One delivery at a time.** Throughput is at most one SMTP transaction per `min_interval` plus the round trip, which suits low volume. A large backlog drains slowly.
- **No bounce handling.** A server that accepts a message and bounces it later sends the bounce to the envelope sender; the outbox never sees it.
- **No connection reuse.** Each attempt opens a new connection.
- **At least once.** Duplicates are possible.
- **One loop per database**, as described above.
- **Large messages** are held in memory during each attempt, and stored once per recipient.

## Compatibility

- Rust 1.98 or newer (edition 2024). mail-auth's message parser needs 1.98.
- A C compiler on the build machine, for AWS-LC.
- Linux and other Unix systems. Elsewhere the database file gets the platform's default permissions.
- Dependencies: lettre 0.11 (message builder and SMTP client over Tokio and rustls on AWS-LC; no native-tls, no DKIM), mail-auth 0.15 (DKIM signing on AWS-LC), hickory-resolver 0.26 (MX lookups, using the system resolver configuration), rusqlite 0.41 (SQLite bundled, so no system SQLite is needed), tokio 1.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                                  # unit, integration and doc tests
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo deny --locked check                            # advisories, bans, licenses, sources
```

The integration tests run the real lettre transport against a scripted SMTP server on 127.0.0.1, so they need no network. Work test first: write the test, watch it fail for the right reason, then write the code. `docs/ARCHITECTURE.md` describes the internals and has to be kept current with them.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this crate, as defined in the Apache-2.0 license, is dual licensed as above, without any additional terms or conditions.
