# Changelog

All notable changes to this crate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.5] - 2026-11-15

### Changed

- No crate that reads the system CA store is in the tree: rustls-platform-verifier, rustls-native-certs and openssl-probe are gone, so the crate builds and runs in images with no CA bundle. All TLS (SMTP, MTA-STS policy fetch) already verified against webpki-roots. mail-auth's default features turned these on, through hickory; mail-auth is now built with `default-features = false, features = ["aws-lc-rs"]`, from its unreleased commit da47a34eb6 (v0.15.1 plus an optional platform verifier), until that change is released. `deny.toml` allows that git source and now bans rustls-native-certs and rustls-platform-verifier.

## [0.1.4] - 2026-11-15

### Security

- rusqlite 0.39 to 0.41 (libsqlite3-sys 0.39.1, bundled SQLite 3.54.1), which fixes RUSTSEC-2026-0459. `deny.toml` no longer ignores it, and SECURITY.md no longer lists it.

### Changed

- Builds alongside sqlx 0.9.1, which accepts libsqlite3-sys < 0.40. sqlx 0.9.0 (libsqlite3-sys < 0.38) cannot share a build with this release; use 0.1.3 with it.

## [0.1.3] - 2026-11-15

### Changed

- rusqlite 0.42 back to 0.39 (libsqlite3-sys 0.37). sqlx 0.9 accepts only libsqlite3-sys >=0.30.1, <0.38, and Cargo links one `sqlite3` per build, so 0.1.2 could not share a build with it. A dependent that also uses rusqlite directly must use 0.39 as well.

### Security

- The bundled SQLite (libsqlite3-sys 0.37) is older than 3.54 and is affected by RUSTSEC-2026-0459: a database opened together with a crafted `-wal` file of a different page size can return stale process memory. It is local only. See SECURITY.md.

## [0.1.2] - 2026-11-14

### Changed

- Dependencies: rusqlite 0.42 (bundled SQLite via libsqlite3-sys 0.40), rustls-pki-types 1.16, webpki-roots 1.0.12, and compatible updates across the lockfile. aws-lc-rs stays at 1.18.2 so the tree keeps one aws-lc-sys.

## [0.1.1] - 2026-11-07

### Security

- `Route::Mx` connects only to public addresses: each MX host is resolved, special-purpose addresses (loopback, private, link-local, CGNAT, documentation, multicast) are skipped, and TLS is verified for the MX name. At most 10 addresses per attempt, IPv4 first.
- `Route::Mx` applies MTA-STS (RFC 8461): in `enforce` mode only listed MX hosts are used, TLS with a verified certificate is required, and no match defers the message. Policies are fetched over HTTPS from a public address, cached in memory for `max_age`, and never stored on disk. No DANE or TLSRPT.

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

[Unreleased]: https://github.com/bl00dclot/rusty-mailbox/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/bl00dclot/rusty-mailbox/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/bl00dclot/rusty-mailbox/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/bl00dclot/rusty-mailbox/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/bl00dclot/rusty-mailbox/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/bl00dclot/rusty-mailbox/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bl00dclot/rusty-mailbox/releases/tag/v0.1.0
