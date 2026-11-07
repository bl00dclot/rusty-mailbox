# Changelog

All notable changes to this crate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- `Route::Mx` connects only to public addresses: each MX host is resolved, special-purpose addresses (loopback, private, link-local, CGNAT, documentation, multicast) are skipped, and TLS is verified for the MX name. At most 10 addresses per attempt. No MTA-STS or DANE yet.

## [0.1.0] - 2026-11-07

### Added

- `Outbox`: a durable SQLite outbox (WAL, `synchronous=FULL`) that stores one row per envelope recipient and deletes it on delivery, permanent failure or expiry.
- The delivery loop, `Outbox::run`: one attempt at a time, `min_interval` pacing, exponential backoff capped at 2 hours, and a `max_age` deadline.
- `Route::Host` (a smarthost or a pinned MX) and `Route::Mx` (MX lookup, null MX, implicit MX).
- `Tls::Required`, `Tls::Opportunistic`, and `Tls::None` (loopback only).
- DKIM signing at enqueue, with mail-auth on AWS-LC: `Config::dkim(domain, selector, pem)`, RSA keys in PKCS#1 or PKCS#8 PEM. It signs From, To, Cc, Subject, Date, Message-ID, Reply-To, MIME-Version, Content-Type and Content-Transfer-Encoding, over-signed so none can be added in transit, relaxed/relaxed. lettre's `dkim` feature is not used, because it depends on the `rsa` crate (RUSTSEC-2023-0071).
- Deleted rows are gone from every database file: `secure_delete` plus `wal_checkpoint(TRUNCATE)` whenever the delivery loop goes idle after a deletion.
- Minimum Rust version 1.98. A C compiler is needed to build AWS-LC.
- `Event` and `pending()`, both with address redaction. Errors without an SMTP reply are fixed strings.
- `open` sets the database file to mode `0600`, including a file that already exists, and keeps only the parsed DKIM key, not the PEM.
- `Route::Mx` has no MTA-STS or DANE.
- Licensed under MIT OR Apache-2.0.

[Unreleased]: https://github.com/bl00dclot/rusty-mailbox/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bl00dclot/rusty-mailbox/releases/tag/v0.1.0
