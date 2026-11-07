# rusty-mailbox: how it is built

This document is for people changing the crate. The README covers how to use it. Keep this file current: a change to the schema, the loop, the error classification or a guarantee changes this file in the same commit.

## Shape

```text
 caller                         Outbox                                   network
 ──────                         ──────                                   ───────
 enqueue(Message) ──► strip Bcc, DKIM-sign, split per recipient
                      └► INSERT rows in one transaction (fsync) ──► Notify
                                                                     │
 run(shutdown, on_event) ◄───────────────────────────────────────────┘
   loop:
     next due row? ── no ──► sleep until due / woken / 60 s / shutdown
       │ yes
     wait min_interval since the last attempt
     deliver::attempt ──► (MX, MTA-STS, A/AAAA) ──► lettre SMTP + STARTTLS ──► server
     settle: delete (Delivered, Failed, Expired) or reschedule (Deferred)
     on_event(Event)
```

One process owns one SQLite file. `enqueue` and `pending` can be called from any thread; `run` is one task that does every delivery.

## Modules

| File | Owns |
| --- | --- |
| `src/lib.rs` | The public API (`Outbox`, `Config`, `Route`, `Tls`, `Event`, `Pending`, `Error`), the checks in `open`, `enqueue`, the delivery loop (`run`) and what happens to a row after an attempt (`settle`). |
| `src/queue.rs` | The SQLite file: opening it with the right pragmas and permissions, the schema and its migrations, and one function per query. It knows nothing about SMTP. |
| `src/deliver.rs` | One delivery attempt: which hosts to try (`hops`, `mx_hosts`, `sts_hosts`), the MX and address lookups (`public_addrs`, `is_public`), building the lettre transport, classifying the result (`Outcome`), the backoff schedule and `redact`. It knows nothing about SQLite. |
| `src/sts.rs` | MTA-STS (RFC 8461): the `_mta-sts` TXT lookup (`txt_id`), the HTTPS policy fetch, parsing (`parse_policy`, `http_body`), MX matching (`mx_matches`) and the in-memory `Cache` with its rules (`next`). |

`lib.rs` is the only module that touches both: it reads a `queue::Row`, passes it to `deliver::attempt`, and writes the outcome back with `queue`.

## The table

```sql
CREATE TABLE outbox (
  id              INTEGER PRIMARY KEY,
  created_ms      INTEGER NOT NULL,   -- unix milliseconds, at enqueue
  mail_from       TEXT,               -- envelope sender; NULL is the null reverse path
  rcpt            TEXT    NOT NULL,   -- exactly one envelope recipient
  data            BLOB    NOT NULL,   -- the signed message, byte for byte as sent
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_ms INTEGER NOT NULL,   -- unix milliseconds; due when <= now
  last_error      TEXT                -- redacted error of the last failed attempt
) STRICT;
CREATE INDEX outbox_due ON outbox (next_attempt_ms);
```

- **One row per recipient.** A message to three recipients is three rows with the same `data`. Each row succeeds, fails or expires on its own, and a transaction never carries more than one `RCPT TO`, so recipients never see each other's envelope addresses.
- **Times are wall-clock milliseconds**, because they have to survive a restart. The loop uses them only to choose the next row. The pacing gap uses `Instant` instead, which never jumps.
- **The row id is the public id.** `enqueue` returns it, and every `Event` and `Pending` names it. It is SQLite's rowid. Ids of deleted rows can be reused, so an id identifies a row only while the row exists.

### Opening

`queue::open` does, in order:

1. Creates the file if it is missing, with mode `0600` on Unix (`create_private`). SQLite gives the `-wal` and `-shm` files the main file's mode. An existing file is set to `0600` too; on a file owned by another user that fails with EPERM, and `open` refuses it.
2. `PRAGMA journal_mode = WAL`, and checks that it took. Some network file systems refuse WAL; `open` then fails with `Error::Config` instead of running without the durability the guarantees promise.
3. `synchronous = FULL`: every commit syncs the WAL to disk before returning, so a returned `enqueue` survives a power cut.
4. `secure_delete = ON`: deleted rows, including their overflow pages, are overwritten with zeros, so delivered content does not linger in free pages of the main file. On its own that is not enough in WAL mode: the frames that held the row stay in the `-wal` file. The loop truncates that file (see "The delivery loop").
5. `busy_timeout = 5000`, so a brief lock by another connection is waited out rather than failing.
6. Reads `PRAGMA user_version` and migrates.

### Migrations

`user_version` is the schema version, and `SCHEMA_VERSION` in `queue.rs` is the one this build writes.

| `user_version` | Action |
| --- | --- |
| 0 | A new file: create the table and the index, set 1, all in one transaction. |
| `SCHEMA_VERSION` | Nothing to do. |
| anything else | `Error::Config`: the file is from a newer build. Never guess at a newer schema. |

To change the schema: bump `SCHEMA_VERSION`, add a match arm that migrates each older version step by step inside a transaction, ending with `PRAGMA user_version = <new>`, and add a test that opens a file at the old version and checks that a queued row still delivers. Rows in a live queue hold real mail, so a migration must never drop them.

## `enqueue`

1. Removes every `Bcc:` header. lettre already removes it unless the builder called `keep_bcc()`; this makes the guarantee unconditional.
2. Takes the envelope (lettre derives it from `From`/`Sender` and `To`/`Cc`/`Bcc`), sorts and deduplicates the recipients, and serialises the message once with `formatted()`.
3. If DKIM is configured, signs those bytes with the `DkimSigner` built in `open`, and puts the `DKIM-Signature` header in front of them. Signing at enqueue means every retry sends the same bytes, and a key or selector change affects only new mail. A signing failure returns `Error::Dkim`, and nothing is stored.
4. Inserts one row per recipient in a single transaction, so a message is stored for all its recipients or for none.
5. `Notify::notify_one` wakes the loop. If the loop is busy, the notification is kept as a permit and the next wait returns at once, so a wake-up is never lost.

It runs on the caller's thread and blocks on the disk sync.

## The delivery loop (`run`)

```text
loop
  row = first row with next_attempt_ms <= now, ordered by next_attempt_ms, id
  if none:
      if a row was deleted since the last truncate: wal_checkpoint(TRUNCATE)
      wait for the first of: shutdown, an enqueue, the next row's due time, 60 s
      continue
  if there was an earlier attempt: wait until it ended + min_interval (or shutdown)
  outcome = attempt(row)                (abandoned if shutdown resolves first)
  event = settle(row, outcome)          (one UPDATE or DELETE)
  on_event(event)
```

- **One attempt at a time.** One loop over one connection means a row can never be in two attempts at once, so there are no locks or lease columns. The cost is throughput, marked with a `ponytail:` comment in `run`: parallel workers (per destination domain, with a lease column) are the upgrade if a backlog ever has to drain fast.
- **Pacing** waits from the end of the previous attempt, so `min_interval` is the smallest gap between two connections whatever an attempt costs. It applies to every attempt, failed ones too, because a sending cap counts connections, not successes.
- **Truncating the WAL.** In WAL mode a deleted row's content stays in the `-wal` file's frames until the log is reset. So each time the loop goes idle after a `Delivered`, `Failed` or `Expired`, it runs `PRAGMA wal_checkpoint(TRUNCATE)`. That copies the log into the main file, where `secure_delete` has zeroed the rows, and truncates the log to zero bytes. If the checkpoint reports busy, the `residue` flag stays set, and it is tried again at the next idle moment. "Idle" means nothing is due, not that the queue is empty, so a row that waits for days does not keep already-delivered mail in the log. Under load the loop is never idle, so this costs nothing there. `journal_mode = DELETE` was rejected: it needs at least two syncs per transaction, and its unlinked journal leaves freed blocks behind just the same.
- **The 60-second wake-up** covers wall-clock jumps. A row's due time is wall-clock, the sleep is monotonic, and the periodic wake-up keeps them from drifting apart by more than a minute.
- **Shutdown** is checked first in every `select!` (`biased`). Before an attempt starts, it stops the loop with nothing sent. During an attempt, it drops the SMTP future, and the connection closes without the final `.` or before the server's reply. The row is untouched and is sent again on the next run. This is one of the two ways a message can be delivered twice; the other is a `250` that is lost on the way back.
- **The mutex.** The `rusqlite::Connection` sits in a `std::sync::Mutex`. It is held for one query at a time and never across an `.await`, so `run`'s future stays `Send`, and `enqueue` from other threads waits at most one query. A poisoned lock is recovered (`into_inner`), because a panic elsewhere cannot leave a SQLite transaction half-applied.

### Classifying an attempt

`deliver::attempt` returns one of three outcomes:

| What happened | Outcome | Event |
| --- | --- | --- |
| lettre's `send_raw` returned `Ok` (2xx after `DATA`) | `Delivered` | `Delivered` |
| An SMTP reply with a 5xx code (`is_permanent()`) | `Permanent` | `Failed` |
| An SMTP reply with a 4xx code (`status()` is set) | `Transient` | `Deferred` or `Expired` |
| No SMTP reply: connection refused, timeout, TLS handshake or certificate failure, an unparseable reply | the next host; `Transient` after the last one, with a fixed string (`no_reply`) | `Deferred` or `Expired` |
| MX lookup: NXDOMAIN | `Permanent` | `Failed` |
| MX lookup: null MX (a `.` exchange) | `Permanent` | `Failed` |
| MX lookup: no MX records | try the domain itself | |
| MTA-STS `enforce`, and no MX host matches the policy | `Transient` | `Deferred` or `Expired` |
| MX hosts resolve, but to no public address (`is_public`) | `Permanent` | `Failed` |
| MX hosts: no public address, and a lookup failed | `Transient` | `Deferred` or `Expired` |
| MX lookup: any other DNS error, or no resolver configuration | `Transient` | `Deferred` or `Expired` |
| The stored sender or recipient no longer parses | `Permanent` | `Failed` |

"The next host" applies to `Route::Mx` only; `Route::Host` has one host. Moving on only when there was no SMTP reply follows RFC 5321 for connection failures, and avoids sending the same message to a second MX after the first one already replied.

### Settling a row

`settle` turns the outcome into one database write and one event:

- `Delivered` and `Permanent` delete the row.
- `Transient`:
  - If `now >= created_ms + max_age`, the row is deleted, and `Expired` fires.
  - Otherwise `attempts` goes up by 1 and `last_error` is saved. `next_attempt_ms` becomes `min(now + backoff(attempts), created_ms + max_age)`.

`backoff(n) = min(retry_base × 2^(n−1), 2 h)`, with saturating arithmetic. With the defaults (60 s, 7 days) the gaps are 1, 2, 4, 8, 16, 32 and 64 minutes, then 2 hours: 91 attempts in all, the last one at the 7-day deadline.

Clamping to the deadline means the last attempt happens exactly at `max_age`, and a row that fails then is deleted then, never a backoff later. A row can outlive `max_age` only while the loop is not running (the process is down). It then gets one more attempt when the loop starts, and is deleted if that fails.

## SMTP and TLS

The transport is built fresh for every host of every attempt (`deliver::transport`):

```rust,ignore
AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(addr)
    .port(port)
    .tls(/* Required | Opportunistic | None */)
    .hello_name(ClientId::Domain(helo))
    .credentials(/* only with Required, checked in open */)
```

- `builder_dangerous` means "no TLS preset". It is safe here because `.tls(...)` is always set from `Tls`, and `open` already refused the unsafe combinations.
- `TlsParameters::new(name)` verifies the certificate chain against webpki-roots, the Mozilla root store compiled into the binary, and checks the name against `name`. With `Route::Host`, the connection and the name are both `host`. With `Route::Mx`, the connection goes to an address that `public_addrs` resolved and checked, and `name` is the MX host from DNS. Connecting to the checked address, instead of letting lettre resolve the name again, means a second DNS answer cannot swap in an internal address.
- With `Opportunistic`, lettre sends `STARTTLS` only if `EHLO` offered it. If the handshake then fails, the attempt fails; there is no fallback to plain text after a failed handshake.
- lettre's default timeout (60 s per command) applies. There is no connection pool (lettre's `pool` feature is off), so every attempt pays one TCP and TLS handshake. At low volume that is cheaper than keeping idle connections.
- `send_raw` takes the stored bytes as they are, so lettre never re-encodes them, and the DKIM signature stays valid.

`Route::Mx` creates one `hickory_resolver::TokioResolver` on its first lookup, and keeps it for the life of `run`. It reads the system resolver configuration (`/etc/resolv.conf`). The lookup is for `<domain>.` (fully qualified), so no search domains are added.

## DKIM

DKIM is signed with mail-auth's DKIM1 signer, on AWS-LC, not with lettre's `dkim` feature. lettre's feature uses the pure-Rust `rsa` crate, which has RUSTSEC-2023-0071 (Marvin: non-constant-time modular exponentiation, so signing time leaks the key) with no fixed release. lettre is built without `dkim`, and its TLS also runs on AWS-LC (`tokio1-rustls`, `aws-lc-rs`, `webpki-roots`), so neither `rsa` nor `ring` is in the tree. CI fails if either comes back.

`Config::dkim(domain, selector, pem)` stores the PEM as a string. `open` takes it out of the config and turns it into a signer once (`signer` in `lib.rs`), so the `Outbox` keeps only the parsed key:

```rust,ignore
let der = PrivateKeyDer::from_pem_slice(pem)?;            // PKCS#1 or PKCS#8
let key = RsaKey::<Sha256>::from_key_der(der)?;
DkimSigner::from_key(key).domain(domain).selector(selector).headers(SIGNED_HEADERS)
```

`enqueue` calls `sign(&formatted)` and writes `signature.to_header()` (which ends in CRLF) in front of the message bytes.

- `SIGNED_HEADERS` lists `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `Reply-To`, `MIME-Version`, `Content-Type` and `Content-Transfer-Encoding`, each named twice. mail-auth signs every instance of a listed header that is present, then adds one `h=` entry for each listed name it did not match, which a verifier reads as an empty header. Naming each header twice therefore over-signs it: one extra empty entry for a present header, so a second `From:` added in transit breaks the signature, and the same for an absent one such as `Cc` (`added_identity_header_fails_verification`).
- Canonicalization is mail-auth's default, `relaxed/relaxed`. That survives the line-ending and whitespace changes that relays make.
- `Bcc` is never in the signed bytes: it is removed from the message before `formatted()`.
- RSA only, marked `ponytail:` on `Config::dkim`. mail-auth can also sign Ed25519; adding it is an algorithm argument and a second key type.

## Privacy

The rule, which is also in `CLAUDE.md`: no address and no message content ever leaves the crate except as mail on the wire.

- The crate has no logging dependency and prints nothing.
- `Event` and `Pending` carry only the row id, times, counts and an error string.
- Every error string passes through `deliver::redact`, which replaces each whitespace-separated word containing `@` with `[address]`, and cuts the text at 500 characters. Server replies are where addresses usually leak: `550 5.1.1 <user@example.net> unknown`.
- DNS errors are replaced with fixed strings ("MX lookup failed", "recipient domain does not exist", "mail host lookup failed", "mail host has no public address"), because hickory's messages name the domain that was queried.
- Errors without an SMTP reply become a fixed class in `deliver::no_reply` ("connection failed", "TLS failure", "timed out", "bad SMTP reply"), because lettre's source chain can name the recipient's MX host. `redact` is used only for real server replies.
- `queue::pending` selects only the id, times, attempt count and error columns, never `mail_from`, `rcpt` or `data`.
- The MTA-STS cache (`sts::Cache`) holds recipient domains, in memory only, for each policy's `max_age` (at most a year). It is never written to the database.

## Tests

`cargo test` runs three suites.

**Unit tests** (`src/deliver.rs`), pure functions with no network:

- `backoff` gives 60, 120, … 3840, then 7200 and stays there; a base of 0 stays 0.
- `mx_hosts` sorts by preference and strips the trailing dot. A `.` exchange is a null MX. No records means the domain itself.
- `hops` for `Route::Mx` connects to the checked address, verifies TLS for the MX name, and gives port 25, the configured `Tls`, the configured HELO and no credentials.
- `is_public` refuses every special-purpose IPv4 and IPv6 block (IANA registries), checks the IPv4 address inside mapped and NAT64 addresses, and passes public unicast.

**Integration tests** (`tests/outbox.rs`) run the real lettre transport through `Route::Host` with `Tls::None` against the fake server in `tests/common/mod.rs`:

| Test | Proves |
| --- | --- |
| `delivers_signed_and_deletes_row` | The row is deleted and `Delivered` fires. The data has `DKIM-Signature` with the right `d=` and `s=`, and the original `Reply-To`. The signature verifies with mail-auth's verifier against the test key's TXT record, and `h=` covers From, To, Cc (absent), Subject, Date, Message-ID and Reply-To. |
| `accepts_pkcs8_key_and_signature_verifies` | A PKCS#8 key opens, and its signature verifies. |
| `tampered_reply_to_fails_verification` | Changing `Reply-To` after signing breaks the signature. |
| `added_identity_header_fails_verification` | Prepending a second `From`, `Reply-To` or `Subject` after signing breaks the signature (over-signing). |
| `one_transaction_per_recipient_without_bcc_header` | To, Cc and Bcc give three transactions with one `RCPT TO` each, and no `Bcc:` header or Bcc address in the data. |
| `transient_failure_defers_then_retries` | A 451 gives `Deferred`; `pending()` shows `attempts = 1` and the 451 text; with `retry_base` 0 the next run delivers. |
| `permanent_failure_deletes_row` | A 550 gives `Failed`, the row is deleted, and the address quoted in the reply is redacted. |
| `no_listener_defers` | Connection refused gives `Deferred` with the fixed error `connection failed`, and the row stays. |
| `mx_route_refuses_a_loopback_host` | `Route::Mx` to `postmaster@localhost` (no MX, so the domain itself, which resolves to loopback) gives `Failed` with "mail host has no public address", and nothing connects. Checked by mutation: without the loopback rule it connects and defers. |
| `sts::tests::*` (unit) | TXT discovery (exactly one `v=STSv1` record, id syntax), policy parsing and limits, `*.` matching one left label, HTTP: only a complete `200 text/plain`, no redirects, no chunking, and a `Content-Length` when TLS ended without `close_notify`; cache: a live policy survives a missing TXT, a new id refetches, a failed fetch waits 5 minutes. Each rule was checked by mutation. |
| `sts_enforce_keeps_matching_mx_and_requires_tls` (unit) | `enforce` keeps only matching hosts and requires TLS; `testing` and no policy change nothing; no match leaves no host. |
| `expires_past_max_age` | With `max_age` 0, a 451 gives `Expired`, and the row is deleted. |
| `survives_reopen` | Enqueue, drop the `Outbox`, open the file again: the message still delivers, once. |
| `open_checks_transport_security` | `Tls::None` to 192.0.2.1 and credentials with `Opportunistic` are refused; `Tls::None` to 127.0.0.1 is allowed. |
| `open_rejects_bad_dkim_key` | A key that does not parse fails `open` with `Error::Dkim`. |
| `paces_deliveries` | With `min_interval` 200 ms, transactions start at least 200 ms apart. |
| `delivered_content_is_gone_from_every_file` | A delivered message large enough to use overflow pages leaves neither its body nor its recipient in the bytes of `.sqlite3`, `-wal` or `-shm` once the loop has gone idle. Checked by mutation: it fails with `secure_delete` off (residue in the main file), and fails without the truncate (residue in `-wal`). |
| `open_tightens_an_existing_database_to_owner_only` | An existing file at mode `0644` is `0600` after `open` (Unix). |

The fake server (`FakeSmtp::start(replies)`) listens on 127.0.0.1 on a random port. It answers `EHLO` with `8BITMIME`, accepts `MAIL` and `RCPT`, and records each transaction: sender, recipients, data and start time. It answers each end of `DATA` with the next scripted reply, then `250 ok` for good. Scripting the reply to `DATA`, not to `RCPT`, keeps the script one list long and still exercises lettre's whole path to the classified error. `dead_port()` gives a port with nothing listening. `run_for(outbox, n)` runs the loop until `n` events have fired, then resolves the shutdown future, with a 10-second timeout.

`tests/common/throwaway-test-dkim-key.pem` is a 2048-bit PKCS#1 key made for these tests, `throwaway-test-dkim-key-pkcs8.pem` is the same key as PKCS#8, and `throwaway-test-dkim-record.txt` is its DNS record. `dkim_verifies` in `tests/common/mod.rs` verifies a message with mail-auth, answering the one TXT lookup from an in-memory `DnsCache`, so no DNS query is made. The fake server keeps the data byte-exact (CRLF, dot-stuffing undone), which verification needs. The key signs nothing real.

**Doc tests**: every Rust block in the README compiles (`no_run`), so the usage guide cannot fall behind the API.

The two things not tested in CI are TLS and real DNS lookups, because both need the network or a CA. `sts::tests::fetches_a_real_policy` (ignored; run it with `cargo test --lib -- --ignored`) fetches gmail.com's live MTA-STS policy end to end. They are thin calls into lettre and hickory, which test them. The first real send is the end-to-end check.

## Dependencies

| Crate | Features | Why |
| --- | --- | --- |
| lettre 0.11 | `builder`, `smtp-transport`, `tokio1-rustls`, `webpki-roots`, `aws-lc-rs` (default features off) | Message builder, SMTP client and STARTTLS. The defaults would pull in native-tls (OpenSSL) and `hostname`; `dkim` would pull in `rsa`; `tokio1-rustls-tls` would pull in `ring`. |
| mail-auth 0.15 | defaults (`aws-lc-rs`, `dns-hickory`) | DKIM signing on AWS-LC. A DNS backend is mandatory; it shares hickory 0.26 with this crate. It also brings mail-parser, which sets the 1.98 minimum Rust version. |
| rustls-pki-types 1.15 | | `PrivateKeyDer::from_pem_slice`, to read PKCS#1 and PKCS#8 PEM. Already in the tree through rustls. |
| hickory-resolver 0.26 | defaults (`tokio`, `system-config`) | MX lookups that tell NXDOMAIN, "no records" and other failures apart. |
| rusqlite 0.41 | `bundled` | SQLite compiled in, so the host needs no SQLite package and the version is fixed. |
| tokio 1 | `macros`, `sync`, `time`, `net`, `io-util` | `select!`, `Notify`, sleeps, and the TCP connection for the MTA-STS fetch. The caller provides the runtime. |
| tokio-rustls 0.26 | `aws_lc_rs`, `tls12` (default features off) | TLS for the MTA-STS policy fetch. Already in the tree through lettre and hickory, so no new crate. |
| webpki-roots 1 | | The Mozilla roots for the MTA-STS fetch, the same store lettre uses. Already in the tree. |

`Cargo.lock` is committed, and CI runs with `--locked`.

Rejected alternatives:

- **`mailrs-outbound-queue`**: 6 months old, 567 downloads and 6 major versions in 5 months, with its own SMTP and DKIM stack and no storage backend.
- **A local Postfix or OpenSMTPD**: a second queue to configure, secure and watch, holding the same mail in a second place.

## Known limits and where to extend

The deliberate shortcuts are marked `ponytail:` in the code:

- `src/lib.rs`, `run`: one delivery at a time. The upgrade is per-domain workers with a lease column.
- `src/deliver.rs`, `attempt`: no DANE (RFC 7672). It needs a DNSSEC-validating resolver and TLSA checks inside the TLS verifier.
- `src/sts.rs`, `policy`: a live policy whose new id fails to fetch is refetched on every attempt. No TLSRPT (RFC 8460), so `testing` mode only delivers.

Also not built: bounce processing, connection reuse, Ed25519 DKIM, and a lock that stops two processes running the loop on one file.

## CI

`.github/workflows/ci.yml` runs on every push and pull request. It installs stable Rust with clippy and rustfmt, then runs:

- `cargo fmt --check`
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo test --locked`
- `cargo doc --no-deps --locked` with `RUSTDOCFLAGS=-D warnings`
- `cargo deny --locked check`, through `EmbarkStudios/cargo-deny-action` (cargo-deny 0.20.2, prebuilt) with `deny.toml`:
  - **advisories:** the RustSec database, with yanked crates denied.
  - **bans:**
    - `rsa`, `ring`, `openssl-sys` and `native-tls` are denied outright.
    - A second version of `aws-lc-sys` or `aws-lc-rs` is denied. mail-auth links `aws-lc-sys` directly, so `Cargo.lock` pins `aws-lc-rs` to the release that uses the same `aws-lc-sys` (1.18.2 for mail-auth 0.15.1). Raise that pin only together with mail-auth.
    - Other duplicate versions only warn.
  - **licenses:** an allow-list of permissive licenses (MIT, Apache-2.0, ISC, BSD-3-Clause, Unicode-3.0, Zlib, 0BSD, CDLA-Permissive-2.0). This crate itself is skipped while it is unpublished and unlicensed.
  - **sources:** crates.io only.

A second job runs `cargo test --locked` on Rust 1.98, the minimum version.

Both jobs restore and save the build cache with `Swatinem/rust-cache`, so AWS-LC and SQLite are compiled from C only when the lockfile or toolchain changes. Every action is pinned to a full commit SHA. Dependabot proposes cargo and GitHub Actions updates weekly.
