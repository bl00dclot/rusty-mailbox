//! Scripted fake SMTP server on 127.0.0.1 for the integration tests.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Throwaway key generated for these tests only (`openssl genrsa -traditional 2048`, 6 Nov 2026).
/// It is public in this repository and must never sign real mail.
pub const DKIM_KEY: &str = include_str!("throwaway-test-dkim-key.pem");
/// The same key as PKCS#8 (`openssl pkcs8 -topk8 -nocrypt`).
pub const DKIM_KEY_PKCS8: &str = include_str!("throwaway-test-dkim-key-pkcs8.pem");
/// The DNS TXT record for the test key.
pub const DKIM_RECORD: &str = include_str!("throwaway-test-dkim-record.txt");

/// One completed `MAIL FROM` .. end-of-`DATA` exchange.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub mail_from: String,
    pub rcpts: Vec<String>,
    pub data: String,
    pub started: Instant,
}

pub struct FakeSmtp {
    pub port: u16,
    pub transactions: Arc<Mutex<Vec<Transaction>>>,
}

impl FakeSmtp {
    /// Answers each end-of-`DATA` with the next scripted reply, then `250 ok` forever.
    pub async fn start(replies: &[&str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let transactions = Arc::new(Mutex::new(Vec::new()));
        let replies: Arc<Mutex<VecDeque<String>>> =
            Arc::new(Mutex::new(replies.iter().map(|r| r.to_string()).collect()));
        let log = transactions.clone();
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let (log, replies) = (log.clone(), replies.clone());
                tokio::spawn(async move {
                    let (read, mut write) = socket.into_split();
                    let mut lines = BufReader::new(read).lines();
                    write.write_all(b"220 fake ESMTP\r\n").await.unwrap();
                    let mut tx: Option<Transaction> = None;
                    while let Ok(Some(line)) = lines.next_line().await {
                        let upper = line.to_ascii_uppercase();
                        let reply = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                            "250-fake\r\n250 8BITMIME".to_string()
                        } else if upper.starts_with("MAIL FROM:") {
                            tx = Some(Transaction {
                                mail_from: line[10..].to_string(),
                                rcpts: Vec::new(),
                                data: String::new(),
                                started: Instant::now(),
                            });
                            "250 ok".to_string()
                        } else if upper.starts_with("RCPT TO:") {
                            tx.as_mut().unwrap().rcpts.push(line[8..].to_string());
                            "250 ok".to_string()
                        } else if upper == "DATA" {
                            write.write_all(b"354 go ahead\r\n").await.unwrap();
                            let mut data = String::new();
                            while let Ok(Some(l)) = lines.next_line().await {
                                if l == "." {
                                    break;
                                }
                                // Undo dot-stuffing, keep CRLF: the data is byte-exact.
                                data.push_str(l.strip_prefix('.').unwrap_or(&l));
                                data.push_str("\r\n");
                            }
                            let mut t = tx.take().unwrap();
                            t.data = data;
                            log.lock().unwrap().push(t);
                            replies
                                .lock()
                                .unwrap()
                                .pop_front()
                                .unwrap_or_else(|| "250 ok".into())
                        } else if upper == "QUIT" {
                            let _ = write.write_all(b"221 bye\r\n").await;
                            break;
                        } else {
                            "250 ok".to_string()
                        };
                        write
                            .write_all(format!("{reply}\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                });
            }
        });
        FakeSmtp { port, transactions }
    }

    pub fn transactions(&self) -> Vec<Transaction> {
        self.transactions.lock().unwrap().clone()
    }
}

/// A loopback port with nothing listening.
pub async fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// A fresh database path under the system temp dir, unique per test process and name.
pub fn db_path(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rusty-mailbox-test-{}-{name}.sqlite3",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

/// Verifies the DKIM signatures in `raw` with mail-auth, answering the one TXT lookup
/// for `selector._domainkey.domain` from a cache, so no DNS query is made.
pub async fn dkim_verifies(raw: &[u8], selector: &str, domain: &str) -> bool {
    use mail_auth::dkim::record::DomainKey;
    use mail_auth::dns::TxtRecordParser;
    use mail_auth::{
        AuthenticatedMessage, DkimResult, DnsCache, MessageAuthenticator, Mx, Negative, Parameters,
        RecordSet, ResolverCache, TxtRecord,
    };
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use std::hash::Hash;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    struct MapCache<K, V>(Mutex<HashMap<K, V>>);
    impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for MapCache<K, V> {
        fn get<Q>(&self, name: &Q) -> Option<V>
        where
            K: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().get(name).cloned()
        }
        fn remove<Q>(&self, name: &Q) -> Option<V>
        where
            K: Borrow<Q>,
            Q: Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().remove(name)
        }
        fn insert(&self, key: K, value: V, _: std::time::Instant) {
            self.0.lock().unwrap().insert(key, value);
        }
    }
    fn empty<K, V>() -> MapCache<K, V> {
        MapCache(Mutex::new(HashMap::new()))
    }
    type Answer<T> = Result<RecordSet<T>, Negative>;
    struct Caches {
        txt: MapCache<Box<str>, TxtRecord>,
        mx: MapCache<Box<str>, Answer<Mx>>,
        ipv4: MapCache<Box<str>, Answer<Ipv4Addr>>,
        ipv6: MapCache<Box<str>, Answer<Ipv6Addr>>,
        ptr: MapCache<IpAddr, Answer<Box<str>>>,
    }
    impl DnsCache for Caches {
        type Txt = MapCache<Box<str>, TxtRecord>;
        type Mx = MapCache<Box<str>, Answer<Mx>>;
        type Ipv4 = MapCache<Box<str>, Answer<Ipv4Addr>>;
        type Ipv6 = MapCache<Box<str>, Answer<Ipv6Addr>>;
        type Ptr = MapCache<IpAddr, Answer<Box<str>>>;
        fn txt(&self) -> Option<&Self::Txt> {
            Some(&self.txt)
        }
        fn mx(&self) -> Option<&Self::Mx> {
            Some(&self.mx)
        }
        fn ipv4(&self) -> Option<&Self::Ipv4> {
            Some(&self.ipv4)
        }
        fn ipv6(&self) -> Option<&Self::Ipv6> {
            Some(&self.ipv6)
        }
        fn ptr(&self) -> Option<&Self::Ptr> {
            Some(&self.ptr)
        }
    }

    let caches = Caches {
        txt: empty(),
        mx: empty(),
        ipv4: empty(),
        ipv6: empty(),
        ptr: empty(),
    };
    let key = DomainKey::parse(DKIM_RECORD.trim().as_bytes()).unwrap();
    caches.txt.insert(
        format!("{selector}._domainkey.{domain}.").into_boxed_str(),
        TxtRecord::from(key),
        std::time::Instant::now(),
    );
    let message = AuthenticatedMessage::parse(raw).expect("message parses");
    let authenticator = MessageAuthenticator::new_cloudflare().unwrap();
    let results = authenticator
        .verify_dkim(Parameters::new(&message).with_cache(&caches))
        .await;
    !results.is_empty() && results.iter().all(|r| *r.result() == DkimResult::Pass)
}
