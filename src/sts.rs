//! MTA-STS (RFC 8461) for `Route::Mx`: policy discovery, fetch and an in-memory cache.
//!
//! Policies are cached in memory only, never in the database, so no recipient domain
//! outlives the process.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// RFC 8461 suggests one minute; the delivery loop is single, so less.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A 64 KiB policy (the RFC's suggested limit) plus room for the response headers.
const MAX_RESPONSE: usize = 72 * 1024;
/// How long a failed fetch for one policy id is remembered (RFC 8461 §3.3: at least 5 min).
const RETRY_FETCH: Duration = Duration::from_secs(5 * 60);
const MAX_AGE_LIMIT: u64 = 31_557_600;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Policy {
    pub mode: Mode,
    pub mx: Vec<String>,
    pub max_age: u64,
}

/// What the `_mta-sts` TXT lookup said.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Txt {
    Id(String),
    Absent,
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Next {
    Use(Option<Policy>),
    Fetch(String),
}

#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub id: String,
    /// `None`: the fetch for this id failed; not retried until `until`.
    pub policy: Option<Policy>,
    pub until: Instant,
}

/// Policies by recipient domain, and the TLS client used to fetch them.
#[derive(Default)]
pub(crate) struct Cache {
    entries: HashMap<String, Entry>,
    tls: Option<Arc<ClientConfig>>,
}

/// The policy id from the `_mta-sts` TXT records, or `None` for no policy (§3.1).
pub(crate) fn txt_id(records: &[Vec<u8>]) -> Option<String> {
    let mut sts = records.iter().filter(|r| r.starts_with(b"v=STSv1;"));
    let record = std::str::from_utf8(sts.next()?).ok()?;
    if sts.next().is_some() {
        return None;
    }
    let id = record
        .split(';')
        .skip(1)
        .find_map(|field| field.trim().strip_prefix("id="))?;
    ((1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| id.to_string())
}

/// A policy file (§3.2), or `None` if it is invalid.
pub(crate) fn parse_policy(body: &str) -> Option<Policy> {
    let (mut version, mut mode, mut max_age, mut mx) = (None, None, None, Vec::new());
    for line in body.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        // A repeated field keeps its first value; `mx` repeats by design.
        match key.trim() {
            "version" => _ = version.get_or_insert(value),
            "mode" => _ = mode.get_or_insert(value),
            "max_age" => _ = max_age.get_or_insert(value),
            "mx" => mx.push(value.to_string()),
            _ => {}
        }
    }
    if version? != "STSv1" {
        return None;
    }
    let mode = match mode? {
        "enforce" => Mode::Enforce,
        "testing" => Mode::Testing,
        "none" => Mode::None,
        _ => return None,
    };
    let max_age = max_age?;
    if max_age.is_empty() || max_age.len() > 10 || !max_age.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let max_age: u64 = max_age.parse().ok().filter(|n| *n <= MAX_AGE_LIMIT)?;
    if mode != Mode::None && mx.is_empty() {
        return None;
    }
    Some(Policy { mode, mx, max_age })
}

/// Whether `host` matches one of the policy's `mx` patterns (§4.1): exactly, or `*.`
/// standing for exactly one left-most label.
pub(crate) fn mx_matches(policy: &Policy, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    policy.mx.iter().any(|pattern| {
        let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
            None => host == pattern,
        }
    })
}

/// The body of an HTTP response if it is a complete `200` with `text/plain` (§3.3: no
/// redirects). `need_length`: the TLS stream ended without `close_notify`, so only a
/// body whose `Content-Length` proves it complete is accepted; a truncated policy could
/// otherwise weaken itself.
pub(crate) fn http_body(response: &[u8], need_length: bool) -> Option<&str> {
    let end = response.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&response[..end]).ok()?;
    let body = std::str::from_utf8(&response[end + 4..]).ok()?;
    let mut lines = head.split("\r\n");
    let mut status = lines.next()?.split(' ');
    if !status.next()?.starts_with("HTTP/1.") || status.next()? != "200" {
        return None;
    }
    let (mut text_plain, mut length) = (false, None);
    for line in lines {
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-type") {
            let media = value.split(';').next().unwrap_or_default().trim();
            text_plain = media.eq_ignore_ascii_case("text/plain");
        } else if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse::<usize>().ok()?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
    }
    match length {
        _ if !text_plain => None,
        Some(n) if n != body.len() => None,
        None if need_length => None,
        _ => Some(body),
    }
}

/// Whether to use a cached policy or fetch one (§5.1). A live cache entry survives a
/// missing or failed TXT lookup; a new id means a new policy.
pub(crate) fn next(entry: Option<&Entry>, txt: Txt, now: Instant) -> Next {
    match (entry.filter(|e| now < e.until), txt) {
        (Some(e), Txt::Id(id)) if id != e.id => Next::Fetch(id),
        (Some(e), _) => Next::Use(e.policy.clone()),
        (None, Txt::Id(id)) => Next::Fetch(id),
        (None, _) => Next::Use(None),
    }
}

/// The policy that applies to mail for `domain`: `Some` only in `enforce` or `testing`
/// mode. Any failure means no policy, unless a cached one is still live (§5.1).
pub(crate) async fn policy(
    cache: &mut Cache,
    resolver: &TokioResolver,
    domain: &str,
) -> Option<Policy> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let txt = match resolver.txt_lookup(format!("_mta-sts.{domain}.")).await {
        Ok(lookup) => {
            let records: Vec<Vec<u8>> = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(txt.txt_data.concat()),
                    _ => None,
                })
                .collect();
            txt_id(&records).map_or(Txt::Absent, Txt::Id)
        }
        Err(e) if e.is_nx_domain() || e.is_no_records_found() => Txt::Absent,
        Err(_) => Txt::Failed,
    };
    let now = Instant::now();
    let policy = match next(cache.entries.get(&domain), txt, now) {
        Next::Use(policy) => policy,
        Next::Fetch(id) => match fetch(cache, resolver, &domain).await {
            Some(policy) => {
                let until = now + Duration::from_secs(policy.max_age);
                let entry = Entry {
                    id,
                    policy: Some(policy.clone()),
                    until,
                };
                cache.entries.insert(domain, entry);
                Some(policy)
            }
            // ponytail: a live policy whose new id fails to fetch is refetched on every
            // attempt; add a per-id retry time if that ever costs.
            None => match cache.entries.get(&domain).filter(|e| now < e.until) {
                Some(live) if live.policy.is_some() => live.policy.clone(),
                _ => {
                    let entry = Entry {
                        id,
                        policy: None,
                        until: now + RETRY_FETCH,
                    };
                    cache.entries.insert(domain, entry);
                    None
                }
            },
        },
    };
    cache.entries.retain(|_, e| now < e.until);
    policy.filter(|p| p.mode != Mode::None)
}

async fn fetch(cache: &mut Cache, resolver: &TokioResolver, domain: &str) -> Option<Policy> {
    let tls = match &cache.tls {
        Some(tls) => tls.clone(),
        None => cache.tls.insert(tls_config()?).clone(),
    };
    let get = get_policy(tls, resolver, format!("mta-sts.{domain}"));
    tokio::time::timeout(FETCH_TIMEOUT, get).await.ok()?
}

/// `GET https://<host>/.well-known/mta-sts.txt` over HTTP/1.0, so the reply is never
/// chunked. The host must resolve to a public address, like any `Route::Mx` host.
async fn get_policy(
    tls: Arc<ClientConfig>,
    resolver: &TokioResolver,
    host: String,
) -> Option<Policy> {
    let lookup = resolver.lookup_ip(format!("{host}.")).await.ok()?;
    // Up to two public addresses of each family, IPv4 first: resolvers often list IPv6
    // first, and not every host can reach IPv6.
    let public: Vec<_> = lookup
        .iter()
        .filter(|ip| crate::deliver::is_public(*ip))
        .collect();
    let v4 = public.iter().filter(|ip| ip.is_ipv4()).take(2);
    let v6 = public.iter().filter(|ip| ip.is_ipv6()).take(2);
    let mut tcp = None;
    for &addr in v4.chain(v6) {
        let connect = TcpStream::connect((addr, 443));
        if let Ok(Ok(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            tcp = Some(stream);
            break;
        }
    }
    let tcp = tcp?;
    let name = ServerName::try_from(host.clone()).ok()?;
    let mut stream = TlsConnector::from(tls).connect(name, tcp).await.ok()?;
    let request = format!(
        "GET /.well-known/mta-sts.txt HTTP/1.0\r\nHost: {host}\r\nUser-Agent: rusty-mailbox\r\nAccept: text/plain\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    let limit = MAX_RESPONSE as u64 + 1;
    let need_length = match (&mut stream).take(limit).read_to_end(&mut response).await {
        Ok(_) => false,
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => true,
        Err(_) => return None,
    };
    if response.len() > MAX_RESPONSE {
        return None;
    }
    parse_policy(http_body(&response, need_length)?)
}

/// Certificates are verified against the Mozilla roots for the policy host name (§3.3).
fn tls_config() -> Option<Arc<ClientConfig>> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Some(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforce(mx: &[&str]) -> Policy {
        Policy {
            mode: Mode::Enforce,
            mx: mx.iter().map(|s| s.to_string()).collect(),
            max_age: 86400,
        }
    }

    /// Live network check of discovery and the HTTPS fetch:
    /// `cargo test --lib -- --ignored fetches_a_real_policy`.
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn fetches_a_real_policy() {
        let resolver = TokioResolver::builder_tokio().unwrap().build().unwrap();
        let mut cache = Cache::default();
        let policy = policy(&mut cache, &resolver, "gmail.com")
            .await
            .expect("no policy");
        assert_eq!(policy.mode, Mode::Enforce);
        assert!(
            mx_matches(&policy, "gmail-smtp-in.l.google.com"),
            "{policy:?}"
        );
        assert!(!mx_matches(&policy, "mx.evil.example"));
        // Cached: the same TXT id needs no second fetch.
        assert!(
            cache
                .entries
                .get("gmail.com")
                .is_some_and(|e| e.policy.is_some())
        );
    }

    #[test]
    fn txt_needs_exactly_one_stsv1_record() {
        let r = |s: &str| s.as_bytes().to_vec();
        assert_eq!(
            txt_id(&[r("v=STSv1; id=20160831085700Z;")]),
            Some("20160831085700Z".into())
        );
        assert_eq!(txt_id(&[r("v=STSv1;id=abc")]), Some("abc".into()));
        // Other TXT records at the name are ignored.
        assert_eq!(
            txt_id(&[r("something else"), r("v=STSv1; id=a1")]),
            Some("a1".into())
        );
        // Two STSv1 records, none, a bad id, or no id: no policy.
        assert_eq!(txt_id(&[r("v=STSv1; id=a"), r("v=STSv1; id=b")]), None);
        assert_eq!(txt_id(&[]), None);
        assert_eq!(txt_id(&[r("v=STSv1; id=bad-id;")]), None);
        assert_eq!(
            txt_id(&[r(&format!("v=STSv1; id={};", "a".repeat(33)))]),
            None
        );
        assert_eq!(txt_id(&[r("v=STSv1;")]), None);
        assert_eq!(txt_id(&[r("id=abc; v=STSv1;")]), None);
    }

    #[test]
    fn policy_parses_and_validates() {
        let body = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n";
        assert_eq!(
            parse_policy(body),
            Some(Policy {
                mode: Mode::Enforce,
                mx: vec!["mail.example.com".into(), "*.example.net".into()],
                max_age: 604800,
            })
        );
        // LF line endings, unknown fields ignored, the first of a repeated field wins.
        let lf =
            "version: STSv1\nmode: testing\nmode: enforce\nfoo: bar\nmx: a.example\nmax_age: 60\n";
        assert_eq!(parse_policy(lf).unwrap().mode, Mode::Testing);
        // `none` needs no mx.
        assert_eq!(
            parse_policy("version: STSv1\nmode: none\nmax_age: 0\n")
                .unwrap()
                .mode,
            Mode::None
        );
        for bad in [
            "mode: enforce\nmx: a.example\nmax_age: 60\n", // no version
            "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 60\n", // wrong version
            "version: STSv1\nmode: strict\nmx: a.example\nmax_age: 60\n", // bad mode
            "version: STSv1\nmode: enforce\nmax_age: 60\n", // enforce without mx
            "version: STSv1\nmode: enforce\nmx: a.example\n", // no max_age
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -1\n", // bad max_age
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 31557601\n", // over the limit
        ] {
            assert_eq!(parse_policy(bad), None, "{bad}");
        }
    }

    #[test]
    fn mx_patterns_match_exactly_or_one_left_label() {
        let p = enforce(&["mail.example.com", "*.example.net"]);
        assert!(mx_matches(&p, "mail.example.com"));
        assert!(mx_matches(&p, "MAIL.Example.COM"));
        assert!(mx_matches(&p, "mail.example.com."));
        assert!(mx_matches(&p, "mx1.example.net"));
        assert!(!mx_matches(&p, "example.net"));
        assert!(!mx_matches(&p, "a.b.example.net"));
        assert!(!mx_matches(&p, "other.example.com"));
        assert!(!mx_matches(&p, "evilexample.net"));
        assert!(!mx_matches(&p, ".example.net"));
    }

    #[test]
    fn http_body_needs_a_complete_200_text_plain() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\nbody";
        assert_eq!(http_body(ok, false), Some("body"));
        assert_eq!(http_body(ok, true), Some("body"));
        let no_length = b"HTTP/1.0 200 OK\r\ncontent-type: TEXT/PLAIN\r\n\r\nbody";
        assert_eq!(http_body(no_length, false), Some("body"));
        // Truncated without close_notify and nothing proves the length: refused.
        assert_eq!(http_body(no_length, true), None);
        for bad in [
            &b"HTTP/1.1 301 Moved\r\nLocation: https://evil.example/\r\nContent-Type: text/plain\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody",
            b"HTTP/1.1 200 OK\r\n\r\nbody",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\nbody",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
            b"garbage",
        ] {
            assert_eq!(http_body(bad, false), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn cache_follows_the_txt_id() {
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        let entry = Entry {
            id: "a".into(),
            policy: Some(enforce(&["mx.example"])),
            until: later,
        };
        let cached = Next::Use(entry.policy.clone());
        // Same id: use the cache. New id: fetch. TXT gone or lookup failed: keep the cache.
        assert_eq!(next(Some(&entry), Txt::Id("a".into()), now), cached);
        assert_eq!(
            next(Some(&entry), Txt::Id("b".into()), now),
            Next::Fetch("b".into())
        );
        assert_eq!(next(Some(&entry), Txt::Absent, now), cached);
        assert_eq!(next(Some(&entry), Txt::Failed, now), cached);
        // Expired: as if there were no cache.
        let gone = Entry {
            until: now,
            ..entry.clone()
        };
        assert_eq!(
            next(Some(&gone), Txt::Id("a".into()), now),
            Next::Fetch("a".into())
        );
        assert_eq!(next(Some(&gone), Txt::Absent, now), Next::Use(None));
        assert_eq!(next(None, Txt::Failed, now), Next::Use(None));
        // A failed fetch is remembered for its id, so it is not retried on every attempt.
        let failed = Entry {
            id: "a".into(),
            policy: None,
            until: later,
        };
        assert_eq!(
            next(Some(&failed), Txt::Id("a".into()), now),
            Next::Use(None)
        );
        assert_eq!(
            next(Some(&failed), Txt::Id("b".into()), now),
            Next::Fetch("b".into())
        );
    }
}
