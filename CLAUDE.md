# rusty-mailbox

Durable SQLite outbox that delivers `lettre::Message`s over SMTP. `README.md` is the crate doc and the usage guide; `docs/ARCHITECTURE.md` describes the internals.

## Commands

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked          # unit, integration (tests/outbox.rs) and the README doctests
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo deny --locked check    # advisories, bans, licenses, sources (deny.toml); CI runs it
```

MSRV is 1.98 (mail-parser needs it); test with `cargo +1.98 test --locked`.
Never add `rsa` or `ring` to the tree (deny.toml bans them): DKIM is mail-auth on AWS-LC.
Keep one `aws-lc-sys` (deny.toml denies a second): `Cargo.lock` pins `aws-lc-rs` to the version matching mail-auth's `aws-lc-sys`; Dependabot bumps of `aws-lc-rs` alone will fail that check.

## Rules

- Test first: write the test, run it, watch it fail for the right reason, then write the code.
  Integration tests use the scripted fake SMTP server in `tests/common/mod.rs` on 127.0.0.1.
- Never log, print or put into an `Event`/`Pending` an email address or message content.
  Server replies go through `deliver::redact`.
- A row is deleted on delivery, permanent failure or expiry. Never keep content longer.
- Schema changes bump `SCHEMA_VERSION` in `src/queue.rs` and migrate from every older `user_version`.
- `tests/common/throwaway-test-dkim-key.pem` is a test-only key; never use it for real mail.
- A change to the schema, the loop, error classification or a guarantee updates
  `docs/ARCHITECTURE.md` (and README "Guarantees" if it changes) in the same commit.
  Other projects rely on README "Guarantees"; change it deliberately.
- Commit only when asked.
