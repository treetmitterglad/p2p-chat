//! iroh-based transport: QUIC connections over a public relay with NAT traversal.
//!
//! Wraps an [`iroh::Endpoint`] configured with:
//! - ALPN `p2pchat/0`
//! - Public n0 relay by default (`https://relay.iroh.computer/`)
//!
//! A 2-peer chat doesn't need DHT discovery or libp2p-style service muxing; a
//! single ALPN and the relay's "where is this node" lookup is enough.

use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use iroh::{
    EndpointAddr, EndpointId, RelayUrl, SecretKey,
    endpoint::{Connection, Endpoint, QuicTransportConfig, presets},
};

/// Application-Layer Protocol Negotiation identifier for p2pchat.
pub const ALPN: &[u8] = b"p2pchat/0";

/// Default n0 relay URL (NA east production relay).
pub const DEFAULT_RELAY_URL: &str = "https://use1-1.relay.n0.iroh-canary.iroh.link/";

/// Default n0 relay as a parsed [`RelayUrl`] (panics if the constant is invalid,
/// which it always is — it's a static string).
pub fn default_relay_url() -> RelayUrl {
    RelayUrl::from_str(DEFAULT_RELAY_URL).expect("DEFAULT_RELAY_URL is valid")
}

/// Thin wrapper around an iroh endpoint.
#[derive(Clone)]
pub struct Transport {
    endpoint: Endpoint,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("node_id", &self.node_id_hex())
            .finish()
    }
}

impl Transport {
    /// Bind a new transport with a random secret key.
    ///
    /// Connects to the public relay. Waiting for relay connectivity
    /// is optional — use [`ensure_online`](Self::ensure_online) when
    /// you need the endpoint address to include relay URLs.
    pub async fn bind() -> Result<Self> {
        let transport_config = QuicTransportConfig::builder()
            .initial_mtu(1280)
            .build();
        let endpoint = Endpoint::builder(presets::N0)
            .transport_config(transport_config)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| anyhow!("bind iroh endpoint: {e:?}"))?;
        Ok(Self { endpoint })
    }

    /// Bind a new transport using a specific 32-byte ed25519 secret seed.
    /// The corresponding node id is the public key derived from that seed.
    pub async fn bind_with_seed(seed: [u8; 32]) -> Result<Self> {
        let key = SecretKey::from_bytes(&seed);
        let transport_config = QuicTransportConfig::builder()
            .initial_mtu(1280)
            .build();
        let endpoint = Endpoint::builder(presets::N0)
            .transport_config(transport_config)
            .secret_key(key)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| anyhow!("bind iroh endpoint with seed: {e:?}"))?;
        Ok(Self { endpoint })
    }

    /// Wait until the endpoint has contacted a relay server and is dialable
    /// from the internet. Call this before generating a ticket to ensure the
    /// address includes relay URLs.
    pub async fn ensure_online(&self) {
        self.endpoint.online().await;
    }

    /// Borrow the underlying iroh endpoint (for advanced uses).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// This endpoint's 32-byte public key (the NodeID).
    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Hex-encoded node id (64 chars, lowercase).
    pub fn node_id_hex(&self) -> String {
        self.node_id().to_string()
    }

    /// Construct a shareable address for this endpoint.
    ///
    /// If the endpoint has not yet contacted a relay (e.g. if
    /// [`ensure_online`](Self::ensure_online) was not called), the
    /// ticket will fall back to the hard-coded default relay URL.
    pub fn ticket(&self) -> Ticket {
        let addr = self.endpoint.addr();
        let has_relay = addr.relay_urls().next().is_some();
        if !has_relay {
            eprintln!(
                "WARN endpoint addr has no relay URLs (node_id={}), falling back to default",
                self.node_id_hex()
            );
        }
        // If the addr has no relay URLs yet, attach the default relay
        // so the ticket always contains routable information.
        let addr = if has_relay {
            addr
        } else {
            addr.with_relay_url(default_relay_url())
        };
        let ticket = Ticket::from_addr(addr);
        eprintln!("ticket: {ticket}");
        ticket
    }

    /// Connect to a peer by [`EndpointAddr`]. Negotiates ALPN [`ALPN`].
    pub async fn connect(&self, addr: EndpointAddr) -> Result<Connection> {
        use std::time::Duration;

        let remote = addr.id;
        eprintln!("connecting to {remote} via {:?}", addr.relay_urls().next());
        let conn = tokio::time::timeout(Duration::from_secs(30), self.endpoint.connect(addr, ALPN))
            .await
            .map_err(|_| anyhow!("connect to {remote}: timed out after 30s"))?
            .map_err(|e| anyhow!("connect to {remote}: {e:?}"))?;
        Ok(conn)
    }

    /// Accept the next incoming connection. Returns `None` if the endpoint is closed.
    pub async fn accept(&self) -> Result<Option<Connection>> {
        let Some(incoming) = self.endpoint.accept().await else {
            return Ok(None);
        };
        let conn = incoming
            .await
            .map_err(|e| anyhow!("accept incoming: {e:?}"))?;
        Ok(Some(conn))
    }

    /// Close the endpoint gracefully. After this, [`accept`](Self::accept) returns `None`.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// User-shareable address for an endpoint.
///
/// Display/parse format: `<hex_nodeid>` or `<hex_nodeid>@<relay_url>`.
/// The relay URL defaults to the n0 public relay when omitted.
///
/// This is a deliberately minimal ticket format — enough for two peers
/// configured to use the same public relay. A more elaborate encoding
/// (with direct addresses, custom relays, expiry) can be added later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    addr: EndpointAddr,
}

impl Ticket {
    /// Wrap an existing [`EndpointAddr`].
    pub fn from_addr(addr: EndpointAddr) -> Self {
        Self { addr }
    }

    /// Build a ticket from a node id, using the default n0 relay.
    pub fn from_node_id(node_id: EndpointId) -> Self {
        let addr = EndpointAddr::new(node_id).with_relay_url(default_relay_url());
        Self { addr }
    }

    /// Underlying [`EndpointAddr`].
    pub fn addr(&self) -> EndpointAddr {
        self.addr.clone()
    }

    /// The peer this ticket points at.
    pub fn node_id(&self) -> EndpointId {
        self.addr.id
    }
}

impl std::fmt::Display for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = self.addr.id.to_string();
        let relay = self.addr.relay_urls().next();
        match relay {
            Some(url) => write!(f, "{id}@{url}"),
            None => write!(f, "{id}@{}", default_relay_url()),
        }
    }
}

impl FromStr for Ticket {
    type Err = TicketParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (id_str, relay_str) = match s.split_once('@') {
            Some((id, relay)) => (id, Some(relay)),
            None => (s, None),
        };
        let id =
            EndpointId::from_str(id_str).map_err(|e| TicketParseError::NodeId(e.to_string()))?;
        let addr = match relay_str {
            Some(r) => {
                let url =
                    RelayUrl::from_str(r).map_err(|e| TicketParseError::Relay(e.to_string()))?;
                EndpointAddr::new(id).with_relay_url(url)
            }
            None => EndpointAddr::new(id).with_relay_url(default_relay_url()),
        };
        Ok(Self { addr })
    }
}

/// Errors that can occur parsing a [`Ticket`].
#[derive(Debug, thiserror::Error)]
pub enum TicketParseError {
    /// Node id portion could not be parsed.
    #[error("invalid node id: {0}")]
    NodeId(String),
    /// Relay URL portion could not be parsed.
    #[error("invalid relay url: {0}")]
    Relay(String),
}

/// Read exactly `n` bytes from a stream into a fresh `Vec`. Convenience for tests.
#[allow(dead_code)]
pub async fn read_exact_stream(
    mut stream: iroh::endpoint::RecvStream,
    n: usize,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.context("read_exact")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_round_trip_default_relay() {
        let key = SecretKey::from_bytes(&[7u8; 32]);
        let id: EndpointId = key.public();
        let t = Ticket::from_node_id(id);
        let s = t.to_string();
        // New display always includes @relay — even for the default.
        assert!(s.contains('@'), "ticket must include relay URL: {s}");
        let parsed: Ticket = s.parse().expect("parse");
        assert_eq!(parsed, t);
        assert_eq!(parsed.node_id(), id);
    }

    #[test]
    fn ticket_round_trip_custom_relay() {
        let key = SecretKey::from_bytes(&[7u8; 32]);
        let id: EndpointId = key.public();
        let custom = RelayUrl::from_str("https://my-relay.example.com/").unwrap();
        let addr = EndpointAddr::new(id).with_relay_url(custom.clone());
        let t = Ticket::from_addr(addr);
        let s = t.to_string();
        assert!(s.contains('@'), "custom relay must be encoded: {s}");
        let parsed: Ticket = s.parse().expect("parse");
        assert_eq!(parsed.addr.relay_urls().next(), Some(&custom));
    }

    #[test]
    fn ticket_rejects_garbage() {
        let err = "not a key".parse::<Ticket>().unwrap_err();
        match err {
            TicketParseError::NodeId(_) => {}
            other => panic!("expected NodeId error, got {other:?}"),
        }
    }
}
