# Security policy

## Reporting a vulnerability

Report it privately through GitHub: on the repository's **Security** tab, choose **Report a vulnerability**. Do not open a public issue.

Include what you found, how to reproduce it, and which version or commit you tested. You will get an answer within 7 days.

## In scope

- Mail delivered in plain text, or to an unverified host, when the configuration asked for TLS.
- `Route::Mx` connecting to a loopback, private or other non-public address.
- An address or message content reaching an `Event`, `pending()`, or anything else the crate returns.
- A queued message lost after `enqueue` returned `Ok`, or kept after it was delivered, failed or expired.
- A `Bcc` recipient visible to other recipients.

## Known limits, not vulnerabilities

These are documented in the README:

- `Route::Mx` does not implement MTA-STS or DANE, so DNS decides which public host receives the mail.
- Redaction masks words containing `@`. A server reply can still identify a recipient without one (`550 jdoe unavailable`), and a quoted local part containing a space is only partly masked. Connection and TLS errors are fixed strings.
- Delivery is at least once, so duplicates are possible.
- Until the delivery loop next goes idle, recently deleted rows can remain in the SQLite `-wal` file. Disk blocks freed by truncating it keep their bytes until the file system reuses them.
