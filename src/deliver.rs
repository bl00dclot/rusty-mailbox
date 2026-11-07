//! One SMTP delivery attempt.

use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls as SmtpTls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::queue::Row;
use crate::{Config, Route, Tls};

const RETRY_CAP: Duration = Duration::from_secs(2 * 60 * 60);

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
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    pub helo: String,
    pub credentials: Option<Credentials>,
}

/// The connections to try for `route`; `mx` is used only by `Route::Mx`.
pub(crate) fn hops(route: &Route, helo: &str, mx: Vec<String>) -> Vec<Hop> {
    match route {
        Route::Host {
            host,
            port,
            tls,
            credentials,
        } => vec![Hop {
            host: host.clone(),
            port: *port,
            tls: *tls,
            helo: helo.to_string(),
            credentials: credentials.clone(),
        }],
        Route::Mx { tls } => mx
            .into_iter()
            .map(|host| Hop {
                host,
                port: 25,
                tls: *tls,
                helo: helo.to_string(),
                credentials: None,
            })
            .collect(),
    }
}

/// Tries to deliver one row. `resolver` is created on first use by `Route::Mx`.
pub(crate) async fn attempt(
    config: &Config,
    resolver: &mut Option<TokioResolver>,
    row: &Row,
) -> Outcome {
    let Ok(rcpt) = row.rcpt.parse::<Address>() else {
        return Outcome::Permanent("stored recipient does not parse".into());
    };
    let Ok(from) = row.mail_from.as_deref().map(str::parse).transpose() else {
        return Outcome::Permanent("stored sender does not parse".into());
    };
    let Ok(envelope) = Envelope::new(from, vec![rcpt.clone()]) else {
        return Outcome::Permanent("invalid envelope".into());
    };
    let mx = match &config.route {
        Route::Host { .. } => Vec::new(),
        Route::Mx { .. } => match lookup_mx(resolver, rcpt.domain()).await {
            Ok(mx) => mx,
            Err(outcome) => return outcome,
        },
    };
    // ponytail: MX hosts are trusted as DNS returns them; no MTA-STS or DANE yet, so an
    // on-path attacker who spoofs DNS picks the host. Add MTA-STS (RFC 8461) policy fetch
    // and DANE (RFC 7672, needs DNSSEC validation) before relying on Route::Mx for secrecy.
    let mut last = String::from("no host to try");
    for hop in hops(&config.route, &config.helo, mx) {
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

fn transport(
    hop: &Hop,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, lettre::transport::smtp::Error> {
    let tls = match hop.tls {
        Tls::Required => SmtpTls::Required(TlsParameters::new(hop.host.clone())?),
        Tls::Opportunistic => SmtpTls::Opportunistic(TlsParameters::new(hop.host.clone())?),
        Tls::None => SmtpTls::None,
    };
    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&hop.host)
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
    fn mx_route_uses_port_25_tls_and_helo() {
        let route = Route::Mx { tls: Tls::Required };
        let hops = hops(&route, "srv.example", vec!["a.mx".into(), "b.mx".into()]);
        assert_eq!(hops.len(), 2);
        for (hop, host) in hops.iter().zip(["a.mx", "b.mx"]) {
            assert_eq!(hop.host, host);
            assert_eq!(hop.port, 25);
            assert_eq!(hop.tls, Tls::Required);
            assert_eq!(hop.helo, "srv.example");
            assert!(hop.credentials.is_none());
        }
    }
}
