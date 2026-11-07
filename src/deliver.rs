//! One SMTP delivery attempt.

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls as SmtpTls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::queue::Row;
use crate::sts::{self, Mode, Policy};
use crate::{Config, Route, Tls};

const RETRY_CAP: Duration = Duration::from_secs(2 * 60 * 60);

/// At most this many addresses are tried per attempt, so a domain with many MX hosts
/// cannot hold the single delivery loop for many connection timeouts.
const MAX_ADDRS: usize = 10;

pub(crate) enum Outcome {
    Delivered,
    Transient(String),
    Permanent(String),
}

/// Delay before retry number `attempts` (1-based): `base`, doubling, capped at 2 hours.
pub(crate) fn backoff(base: Duration, attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(31);
    base.saturating_mul(1 << doublings).min(RETRY_CAP)
}

/// The hosts to try, best first, from a domain's MX records (`None`: there are none).
/// `Err` is a null MX (RFC 7505): the domain accepts no mail.
pub(crate) fn mx_hosts(
    domain: &str,
    records: Option<Vec<(u16, String)>>,
) -> Result<Vec<String>, ()> {
    let mut records = records.unwrap_or_default();
    if records.is_empty() {
        return Ok(vec![domain.to_string()]);
    }
    if records.iter().any(|(_, host)| host == ".") {
        return Err(());
    }
    records.sort_by_key(|(preference, _)| *preference);
    Ok(records
        .into_iter()
        .map(|(_, host)| host.trim_end_matches('.').to_string())
        .collect())
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Hop {
    /// Where to connect: a host name for `Route::Host`, a checked address for `Route::Mx`.
    pub addr: String,
    /// The name the TLS certificate must match.
    pub name: String,
    pub port: u16,
    pub tls: Tls,
    pub helo: String,
    pub credentials: Option<Credentials>,
}

/// The connections to try for `route`; `mx` (address, MX host name) is used only by
/// `Route::Mx`.
pub(crate) fn hops(route: &Route, helo: &str, mx: Vec<(IpAddr, String)>) -> Vec<Hop> {
    match route {
        Route::Host {
            host,
            port,
            tls,
            credentials,
        } => vec![Hop {
            addr: host.clone(),
            name: host.clone(),
            port: *port,
            tls: *tls,
            helo: helo.to_string(),
            credentials: credentials.clone(),
        }],
        Route::Mx { tls } => mx
            .into_iter()
            .map(|(addr, name)| Hop {
                addr: addr.to_string(),
                name,
                port: 25,
                tls: *tls,
                helo: helo.to_string(),
                credentials: None,
            })
            .collect(),
    }
}

/// State kept across attempts by the delivery loop, for `Route::Mx`.
#[derive(Default)]
pub(crate) struct Net {
    /// Created on first use.
    resolver: Option<TokioResolver>,
    sts: sts::Cache,
}

/// Applies an MTA-STS policy to the MX hosts: in `enforce` mode only matching hosts
/// remain, and `true` says TLS is required. `testing` and no policy change nothing.
pub(crate) fn sts_hosts(policy: Option<&Policy>, hosts: Vec<String>) -> (Vec<String>, bool) {
    match policy {
        Some(p) if p.mode == Mode::Enforce => (
            hosts
                .into_iter()
                .filter(|h| sts::mx_matches(p, h))
                .collect(),
            true,
        ),
        _ => (hosts, false),
    }
}

/// Tries to deliver one row.
pub(crate) async fn attempt(config: &Config, net: &mut Net, row: &Row) -> Outcome {
    let Ok(rcpt) = row.rcpt.parse::<Address>() else {
        return Outcome::Permanent("stored recipient does not parse".into());
    };
    let Ok(from) = row.mail_from.as_deref().map(str::parse).transpose() else {
        return Outcome::Permanent("stored sender does not parse".into());
    };
    let Ok(envelope) = Envelope::new(from, vec![rcpt.clone()]) else {
        return Outcome::Permanent("invalid envelope".into());
    };
    let (mx, sts_enforced) = match &config.route {
        Route::Host { .. } => (Vec::new(), false),
        Route::Mx { .. } => {
            let resolver = &mut net.resolver;
            let hosts = match lookup_mx(resolver, rcpt.domain()).await {
                Ok(hosts) => hosts,
                Err(outcome) => return outcome,
            };
            let policy = match resolver.as_ref() {
                Some(r) => sts::policy(&mut net.sts, r, rcpt.domain()).await,
                None => None,
            };
            let (hosts, enforced) = sts_hosts(policy.as_ref(), hosts);
            if hosts.is_empty() {
                // RFC 8461 §5.1: never a permanent failure; the policy may be updated.
                return Outcome::Transient("no MX host matches the MTA-STS policy".into());
            }
            match public_addrs(resolver, hosts).await {
                Ok(mx) => (mx, enforced),
                Err(outcome) => return outcome,
            }
        }
    };
    // ponytail: MTA-STS but no DANE (RFC 7672, needs a DNSSEC-validating resolver and TLSA
    // checks in the TLS verifier). Without a policy, DNS still picks the MX host.
    let mut last = String::from("no host to try");
    for mut hop in hops(&config.route, &config.helo, mx) {
        if sts_enforced {
            hop.tls = Tls::Required;
        }
        let transport = match transport(&hop) {
            Ok(t) => t,
            Err(e) => return Outcome::Transient(no_reply(&e).into()),
        };
        match transport.send_raw(&envelope, &row.data).await {
            Ok(_) => return Outcome::Delivered,
            Err(e) if e.is_permanent() => return Outcome::Permanent(redact(&e)),
            Err(e) if e.status().is_some() => return Outcome::Transient(redact(&e)),
            // No SMTP reply: the connection or TLS failed. Try the next MX.
            Err(e) => last = no_reply(&e).into(),
        }
    }
    Outcome::Transient(last)
}

async fn lookup_mx(
    resolver: &mut Option<TokioResolver>,
    domain: &str,
) -> Result<Vec<String>, Outcome> {
    let resolver = match resolver {
        Some(r) => r,
        None => resolver.insert(
            TokioResolver::builder_tokio()
                .and_then(|b| b.build())
                .map_err(|_| Outcome::Transient("DNS resolver unavailable".into()))?,
        ),
    };
    // Errors here would name the recipient domain, so they become fixed strings.
    let records = match resolver.mx_lookup(format!("{domain}.")).await {
        Ok(lookup) => Some(
            lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::MX(mx) if mx.exchange.is_root() => Some((mx.preference, ".".into())),
                    RData::MX(mx) => Some((mx.preference, mx.exchange.to_ascii())),
                    _ => None,
                })
                .collect(),
        ),
        Err(e) if e.is_nx_domain() => {
            return Err(Outcome::Permanent("recipient domain does not exist".into()));
        }
        Err(e) if e.is_no_records_found() => None,
        Err(_) => return Err(Outcome::Transient("MX lookup failed".into())),
    };
    mx_hosts(domain, records)
        .map_err(|()| Outcome::Permanent("null MX: the domain accepts no mail".into()))
}

/// Resolves each MX host and keeps only public addresses, so a recipient domain cannot
/// point delivery at loopback or an internal network. The loop connects to the checked
/// address itself; a second lookup at connect time could return a different one.
async fn public_addrs(
    resolver: &mut Option<TokioResolver>,
    hosts: Vec<String>,
) -> Result<Vec<(IpAddr, String)>, Outcome> {
    // `lookup_mx` ran first, so the resolver exists.
    let Some(resolver) = resolver.as_ref() else {
        return Err(Outcome::Transient("DNS resolver unavailable".into()));
    };
    let mut addrs = Vec::new();
    let mut lookup_failed = false;
    for host in hosts {
        match resolver.lookup_ip(format!("{host}.")).await {
            Ok(lookup) => {
                let mut public: Vec<IpAddr> = lookup.iter().filter(|ip| is_public(*ip)).collect();
                // IPv4 first: resolvers often list IPv6 first, and not every host can
                // reach IPv6, so IPv6 alone must not use up MAX_ADDRS.
                public.sort_by_key(IpAddr::is_ipv6);
                addrs.extend(public.into_iter().map(|ip| (ip, host.clone())));
            }
            Err(e) if e.is_nx_domain() || e.is_no_records_found() => {}
            Err(_) => lookup_failed = true,
        }
        if addrs.len() >= MAX_ADDRS {
            break;
        }
    }
    addrs.truncate(MAX_ADDRS);
    match (addrs.is_empty(), lookup_failed) {
        (false, _) => Ok(addrs),
        (true, true) => Err(Outcome::Transient("mail host lookup failed".into())),
        (true, false) => Err(Outcome::Permanent("mail host has no public address".into())),
    }
}

/// Whether `ip` is a globally reachable unicast address, from the IANA special-purpose
/// address registries. `IpAddr::is_global` is still unstable.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224 // multicast, reserved, broadcast
                || (a == 100 && (64..128).contains(&b)) // shared address space (CGNAT)
                || (a == 169 && b == 254)
                || (a == 172 && (16..32).contains(&b))
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19)) // benchmarking
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            // NAT64 well-known prefix: the IPv4 address in the last 32 bits decides.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let o = v6.octets();
                return is_public(IpAddr::V4([o[12], o[13], o[14], o[15]].into()));
            }
            // Only global unicast (2000::/3), minus its special-purpose blocks.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x200) // 2001::/23
                && !(s[0] == 0x2001 && s[1] == 0xdb8) // documentation
                && s[0] != 0x2002 // 6to4
                && (s[0] & 0xfff0) != 0x3ff0 // documentation, 3fff::/20
        }
    }
}

fn transport(
    hop: &Hop,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, lettre::transport::smtp::Error> {
    let tls = match hop.tls {
        Tls::Required => SmtpTls::Required(TlsParameters::new(hop.name.clone())?),
        Tls::Opportunistic => SmtpTls::Opportunistic(TlsParameters::new(hop.name.clone())?),
        Tls::None => SmtpTls::None,
    };
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&hop.addr)
        .port(hop.port)
        .tls(tls)
        .hello_name(ClientId::Domain(hop.helo.clone()));
    if let Some(credentials) = &hop.credentials {
        builder = builder.credentials(credentials.clone());
    }
    Ok(builder.build())
}

/// A fixed class for an error that carries no SMTP reply. lettre's source chain can name
/// the recipient's MX host, so its text is never kept.
fn no_reply(e: &lettre::transport::smtp::Error) -> &'static str {
    if e.is_tls() {
        "TLS failure"
    } else if e.is_timeout() {
        "timed out"
    } else if e.is_response() {
        "bad SMTP reply"
    } else {
        "connection failed"
    }
}

/// The error text with every word that contains `@` replaced: server replies often
/// quote the recipient address.
pub(crate) fn redact(error: &dyn std::fmt::Display) -> String {
    error
        .to_string()
        .split_whitespace()
        .map(|word| {
            if word.contains('@') {
                "[address]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(500)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_two_hours() {
        let base = Duration::from_secs(60);
        let secs: Vec<u64> = (1..=9).map(|n| backoff(base, n).as_secs()).collect();
        assert_eq!(secs, [60, 120, 240, 480, 960, 1920, 3840, 7200, 7200]);
        assert_eq!(backoff(base, 1000).as_secs(), 7200);
        assert_eq!(backoff(Duration::ZERO, 5), Duration::ZERO);
    }

    #[test]
    fn mx_in_preference_order() {
        let records = vec![
            (20, "b.mx.example.".to_string()),
            (10, "a.mx.example.".to_string()),
            (20, "c.mx.example.".to_string()),
        ];
        assert_eq!(
            mx_hosts("example.org", Some(records)).unwrap(),
            ["a.mx.example", "b.mx.example", "c.mx.example"]
        );
    }

    #[test]
    fn null_mx_is_refused() {
        assert!(mx_hosts("example.org", Some(vec![(0, ".".to_string())])).is_err());
    }

    #[test]
    fn no_mx_means_the_domain() {
        assert_eq!(mx_hosts("example.org", None).unwrap(), ["example.org"]);
        assert_eq!(
            mx_hosts("example.org", Some(vec![])).unwrap(),
            ["example.org"]
        );
    }

    #[test]
    fn sts_enforce_keeps_matching_mx_and_requires_tls() {
        use crate::sts::{Mode, Policy};
        let hosts = || vec!["mx1.example.com".to_string(), "evil.example".to_string()];
        let policy = |mode| Policy {
            mode,
            mx: vec!["*.example.com".into()],
            max_age: 60,
        };
        assert_eq!(
            sts_hosts(Some(&policy(Mode::Enforce)), hosts()),
            (vec!["mx1.example.com".to_string()], true)
        );
        // Testing mode and no policy deliver as before (no TLSRPT reports are sent).
        assert_eq!(
            sts_hosts(Some(&policy(Mode::Testing)), hosts()),
            (hosts(), false)
        );
        assert_eq!(sts_hosts(None, hosts()), (hosts(), false));
        // Nothing matches: no host to try, and the attempt is transient (§5.1).
        let none = Policy {
            mx: vec!["other.example".into()],
            ..policy(Mode::Enforce)
        };
        assert_eq!(sts_hosts(Some(&none), hosts()), (vec![], true));
    }

    #[test]
    fn only_public_addresses_pass() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip} passed");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
            "2a00:1450:4001::1a",
            "2606:4700::1111",
            "2001:4860::8888",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip} refused");
        }
    }

    #[test]
    fn mx_route_connects_to_the_address_and_verifies_the_name() {
        let route = Route::Mx { tls: Tls::Required };
        let mx = vec![
            ("192.0.2.10".parse().unwrap(), "a.mx".to_string()),
            ("2001:db8::1".parse().unwrap(), "b.mx".to_string()),
        ];
        let hops = hops(&route, "srv.example", mx);
        assert_eq!(hops.len(), 2);
        for (hop, (addr, name)) in hops
            .iter()
            .zip([("192.0.2.10", "a.mx"), ("2001:db8::1", "b.mx")])
        {
            assert_eq!(hop.addr, addr);
            assert_eq!(hop.name, name);
            assert_eq!(hop.port, 25);
            assert_eq!(hop.tls, Tls::Required);
            assert_eq!(hop.helo, "srv.example");
            assert!(hop.credentials.is_none());
        }
    }
}
