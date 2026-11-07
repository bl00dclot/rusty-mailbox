mod common;

use std::time::Duration;

use common::{DKIM_KEY, DKIM_KEY_PKCS8, FakeSmtp, db_path, dead_port, dkim_verifies};
use rusty_mailbox::lettre::Message;
use rusty_mailbox::lettre::transport::smtp::authentication::Credentials;
use rusty_mailbox::{Config, Error, Event, Outbox, Route, Tls};

fn route(host: &str, port: u16) -> Route {
    Route::Host {
        host: host.into(),
        port,
        tls: Tls::None,
        credentials: None,
    }
}

fn config(port: u16) -> Config {
    Config::new(route("127.0.0.1", port), "test.example")
}

fn message() -> Message {
    Message::builder()
        .from("App <noreply@sender.example>".parse().unwrap())
        .reply_to("Support <support@sender.example>".parse().unwrap())
        .to("info@inbox.example".parse().unwrap())
        .subject("Hello")
        .body(String::from("Hello"))
        .unwrap()
}

/// Runs the loop until `n` events have fired, then shuts it down.
async fn run_for(outbox: &Outbox, n: usize) -> Vec<Event> {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut stop = Some(stop);
    let mut events = Vec::new();
    let run = outbox.run(
        async {
            let _ = stopped.await;
        },
        |e| {
            events.push(e);
            if events.len() == n {
                stop.take().map(|s| s.send(()));
            }
        },
    );
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("loop did not produce the expected events in time")
        .unwrap();
    events
}

#[tokio::test]
async fn delivers_signed_and_deletes_row() {
    let smtp = FakeSmtp::start(&[]).await;
    let cfg = config(smtp.port).dkim("sender.example", "s1", DKIM_KEY);
    let outbox = Outbox::open(db_path("delivers"), cfg).unwrap();
    let ids = outbox.enqueue(message()).unwrap();
    assert_eq!(ids.len(), 1);

    let events = run_for(&outbox, 1).await;
    assert!(matches!(events[..], [Event::Delivered { id }] if id == ids[0]));
    assert!(outbox.pending().unwrap().is_empty());

    let tx = &smtp.transactions()[0];
    assert_eq!(tx.mail_from, "<noreply@sender.example>");
    assert_eq!(tx.rcpts, ["<info@inbox.example>"]);
    assert!(tx.data.contains("DKIM-Signature:"), "{}", tx.data);
    assert!(tx.data.contains("d=sender.example;"), "{}", tx.data);
    assert!(tx.data.contains("s=s1;"), "{}", tx.data);
    assert!(
        dkim_verifies(tx.data.as_bytes(), "s1", "sender.example").await,
        "signature does not verify:\n{}",
        tx.data
    );
    let signed = tx.data.to_ascii_lowercase();
    let h = signed
        .split("h=")
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    // Cc is absent from this message: signed as absent, it cannot be added in transit.
    for name in [
        "from",
        "to",
        "cc",
        "subject",
        "date",
        "message-id",
        "reply-to",
    ] {
        assert!(
            h.split(':').any(|n| n.trim() == name),
            "{name} not signed: h={h}"
        );
    }
    assert!(
        tx.data
            .contains("Reply-To: Support <support@sender.example>"),
        "{}",
        tx.data
    );
}

#[tokio::test]
async fn one_transaction_per_recipient_without_bcc_header() {
    let smtp = FakeSmtp::start(&[]).await;
    let outbox = Outbox::open(db_path("bcc"), config(smtp.port)).unwrap();
    let msg = Message::builder()
        .from("noreply@sender.example".parse().unwrap())
        .to("to@inbox.example".parse().unwrap())
        .cc("cc@inbox.example".parse().unwrap())
        .bcc("hidden@inbox.example".parse().unwrap())
        .subject("s")
        .body(String::from("b"))
        .unwrap();
    assert_eq!(outbox.enqueue(msg).unwrap().len(), 3);

    let events = run_for(&outbox, 3).await;
    assert!(events.iter().all(|e| matches!(e, Event::Delivered { .. })));
    let txs = smtp.transactions();
    let mut rcpts: Vec<_> = txs.iter().map(|t| t.rcpts.join(",")).collect();
    rcpts.sort();
    assert_eq!(
        rcpts,
        [
            "<cc@inbox.example>",
            "<hidden@inbox.example>",
            "<to@inbox.example>"
        ]
    );
    for t in &txs {
        assert!(!t.data.to_ascii_lowercase().contains("bcc:"), "{}", t.data);
        assert!(!t.data.contains("hidden@"), "{}", t.data);
    }
}

#[tokio::test]
async fn transient_failure_defers_then_retries() {
    let smtp = FakeSmtp::start(&["451 4.7.1 try again later"]).await;
    let cfg = config(smtp.port).retry_base(Duration::ZERO);
    let outbox = Outbox::open(db_path("defer"), cfg).unwrap();
    let id = outbox.enqueue(message()).unwrap()[0];

    let events = run_for(&outbox, 1).await;
    assert!(matches!(&events[..], [Event::Deferred { id: i, attempts: 1, .. }] if *i == id));
    let pending = outbox.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert_eq!(pending[0].attempts, 1);
    let err = pending[0].last_error.as_deref().unwrap();
    assert!(
        err.contains("451") && err.contains("try again later"),
        "{err}"
    );

    let events = run_for(&outbox, 1).await;
    assert!(matches!(events[..], [Event::Delivered { id: i }] if i == id));
    assert!(outbox.pending().unwrap().is_empty());
}

#[tokio::test]
async fn permanent_failure_deletes_row() {
    let smtp = FakeSmtp::start(&["550 5.1.1 <info@inbox.example> no such user"]).await;
    let outbox = Outbox::open(db_path("fail"), config(smtp.port)).unwrap();
    let id = outbox.enqueue(message()).unwrap()[0];

    let events = run_for(&outbox, 1).await;
    match &events[..] {
        [Event::Failed { id: i, error }] => {
            assert_eq!(*i, id);
            assert!(error.contains("550"), "{error}");
            assert!(!error.contains('@'), "address leaked into error: {error}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(outbox.pending().unwrap().is_empty());
}

#[tokio::test]
async fn no_listener_defers() {
    let outbox = Outbox::open(db_path("nolistener"), config(dead_port().await)).unwrap();
    outbox.enqueue(message()).unwrap();
    let events = run_for(&outbox, 1).await;
    // No SMTP reply: a fixed class, never lettre's source chain (which can name hosts).
    assert!(
        matches!(&events[..], [Event::Deferred { attempts: 1, error, .. }] if error == "connection failed"),
        "{events:?}"
    );
    assert_eq!(outbox.pending().unwrap().len(), 1);
}

#[tokio::test]
async fn expires_past_max_age() {
    let smtp = FakeSmtp::start(&["451 4.7.1 try again later"]).await;
    let cfg = config(smtp.port).max_age(Duration::ZERO);
    let outbox = Outbox::open(db_path("expire"), cfg).unwrap();
    let id = outbox.enqueue(message()).unwrap()[0];

    let events = run_for(&outbox, 1).await;
    assert!(matches!(events[..], [Event::Expired { id: i, .. }] if i == id));
    assert!(outbox.pending().unwrap().is_empty());
}

#[tokio::test]
async fn survives_reopen() {
    let smtp = FakeSmtp::start(&[]).await;
    let path = db_path("reopen");
    let id = {
        let outbox = Outbox::open(&path, config(smtp.port)).unwrap();
        outbox.enqueue(message()).unwrap()[0]
    };
    let outbox = Outbox::open(&path, config(smtp.port)).unwrap();
    let events = run_for(&outbox, 1).await;
    assert!(matches!(events[..], [Event::Delivered { id: i }] if i == id));
    assert_eq!(smtp.transactions().len(), 1);
}

#[test]
fn open_checks_transport_security() {
    let plain_remote = Config::new(route("192.0.2.1", 25), "test.example");
    assert!(matches!(
        Outbox::open(db_path("refuse-plain"), plain_remote),
        Err(Error::Config(_))
    ));

    let creds_opportunistic = Config::new(
        Route::Host {
            host: "smtp.example".into(),
            port: 587,
            tls: Tls::Opportunistic,
            credentials: Some(Credentials::new("u".into(), "p".into())),
        },
        "test.example",
    );
    assert!(matches!(
        Outbox::open(db_path("refuse-creds"), creds_opportunistic),
        Err(Error::Config(_))
    ));

    assert!(Outbox::open(db_path("allow-loopback"), config(25)).is_ok());
}

#[test]
fn open_rejects_bad_dkim_key() {
    let cfg = config(25).dkim("sender.example", "s1", "not a key");
    assert!(matches!(
        Outbox::open(db_path("bad-dkim"), cfg),
        Err(Error::Dkim(_))
    ));
}

#[tokio::test]
async fn paces_deliveries() {
    let smtp = FakeSmtp::start(&[]).await;
    let cfg = config(smtp.port).min_interval(Duration::from_millis(200));
    let outbox = Outbox::open(db_path("pace"), cfg).unwrap();
    let msg = Message::builder()
        .from("noreply@sender.example".parse().unwrap())
        .to("a@inbox.example".parse().unwrap())
        .to("b@inbox.example".parse().unwrap())
        .to("c@inbox.example".parse().unwrap())
        .subject("s")
        .body(String::from("b"))
        .unwrap();
    outbox.enqueue(msg).unwrap();

    run_for(&outbox, 3).await;
    let txs = smtp.transactions();
    assert_eq!(txs.len(), 3);
    for pair in txs.windows(2) {
        let gap = pair[1].started - pair[0].started;
        assert!(gap >= Duration::from_millis(200), "gap {gap:?}");
    }
}

#[tokio::test]
async fn accepts_pkcs8_key_and_signature_verifies() {
    let smtp = FakeSmtp::start(&[]).await;
    let cfg = config(smtp.port).dkim("sender.example", "s1", DKIM_KEY_PKCS8);
    let outbox = Outbox::open(db_path("pkcs8"), cfg).unwrap();
    outbox.enqueue(message()).unwrap();
    run_for(&outbox, 1).await;
    let tx = &smtp.transactions()[0];
    assert!(dkim_verifies(tx.data.as_bytes(), "s1", "sender.example").await);
}

#[tokio::test]
async fn tampered_reply_to_fails_verification() {
    let smtp = FakeSmtp::start(&[]).await;
    let cfg = config(smtp.port).dkim("sender.example", "s1", DKIM_KEY);
    let outbox = Outbox::open(db_path("tamper"), cfg).unwrap();
    outbox.enqueue(message()).unwrap();
    run_for(&outbox, 1).await;
    let data = smtp.transactions()[0]
        .data
        .replace("support@sender.example", "attacker@evil.example");
    assert!(!dkim_verifies(data.as_bytes(), "s1", "sender.example").await);
}

#[tokio::test]
async fn delivered_content_is_gone_from_every_file() {
    let smtp = FakeSmtp::start(&[]).await;
    let path = db_path("residue");
    let outbox = Outbox::open(&path, config(smtp.port)).unwrap();
    // Large enough to spill into overflow pages, which are freed separately.
    let marker = "RESIDUE-MARKER-7f3a9c";
    let body = format!("{marker}\n").repeat(2000);
    let msg = Message::builder()
        .from("noreply@sender.example".parse().unwrap())
        .to("residue-rcpt@inbox.example".parse().unwrap())
        .subject("s")
        .body(body)
        .unwrap();
    outbox.enqueue(msg).unwrap();
    let events = run_for(&outbox, 1).await;
    assert!(matches!(events[..], [Event::Delivered { .. }]));
    assert!(smtp.transactions()[0].data.contains(marker));

    // The loop goes idle once the row is gone, and that is when the WAL is truncated.
    run_until_idle(&outbox).await;
    for suffix in ["", "-wal", "-shm"] {
        let file = format!("{}{suffix}", path.display());
        let bytes = std::fs::read(&file).unwrap_or_default();
        for needle in [marker.as_bytes(), b"residue-rcpt@inbox.example".as_slice()] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{} still in {file}",
                String::from_utf8_lossy(needle)
            );
        }
    }
}

/// Runs the loop briefly with nothing due, so it reaches its idle point.
async fn run_until_idle(outbox: &Outbox) {
    outbox
        .run(tokio::time::sleep(Duration::from_millis(300)), |e| {
            panic!("unexpected event {e:?}")
        })
        .await
        .unwrap();
}

#[cfg(unix)]
#[test]
fn open_tightens_an_existing_database_to_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = db_path("perms");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(Outbox::open(&path, config(25)).unwrap());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode {mode:o}");
}
