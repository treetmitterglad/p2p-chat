//! SQLite-backed persistence for messages, contacts, and sessions.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, Pool, Sqlite};
use uuid::Uuid;

/// Global chat database.
#[derive(Debug, Clone)]
pub struct Store {
    pool: Pool<Sqlite>,
}

impl Store {
    /// Open (or create) the database at `path`.
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .context("create store dir")?;
            }
        }

        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .context("connect to sqlite")?;

        let s = Self { pool };
        s.migrate().await?;
        Ok(s)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS contacts (
                id          TEXT PRIMARY KEY NOT NULL,
                peer_id     BLOB NOT NULL UNIQUE,
                label       TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL DEFAULT '',
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                verified    INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await
        .context("create contacts table")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages (
                id          TEXT PRIMARY KEY NOT NULL,
                peer_id     BLOB NOT NULL,
                direction   TEXT NOT NULL,
                body        TEXT NOT NULL DEFAULT '',
                is_encrypted INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL,
                read_at     TEXT
            )",
        )
        .execute(&self.pool)
        .await
        .context("create messages table")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_messages_peer_id
             ON messages(peer_id, created_at)",
        )
        .execute(&self.pool)
        .await
        .context("create message index")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                id             TEXT PRIMARY KEY NOT NULL,
                peer_id        BLOB NOT NULL,
                state          TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                handshake_hash BLOB
            )",
        )
        .execute(&self.pool)
        .await
        .context("create sessions table")?;

        Ok(())
    }

    // -- Contacts --

    /// Get all known contacts.
    pub async fn list_contacts(&self) -> Result<Vec<Contact>> {
        let contacts = sqlx::query_as::<_, ContactRow>(
            "SELECT * FROM contacts ORDER BY last_seen DESC",
        )
        .fetch_all(&self.pool)
        .await
        .context("list contacts")?;

        Ok(contacts.into_iter().map(Contact::from_row).collect())
    }

    /// Upsert a contact record.
    pub async fn upsert_contact(&self, contact: &Contact) -> Result<()> {
        sqlx::query(
            "INSERT INTO contacts (id, peer_id, label, fingerprint, first_seen, last_seen, verified)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(peer_id) DO UPDATE SET
                label       = excluded.label,
                fingerprint = excluded.fingerprint,
                last_seen   = excluded.last_seen,
                verified    = excluded.verified",
        )
        .bind(contact.id.to_string())
        .bind(&contact.peer_id[..])
        .bind(&contact.label)
        .bind(&contact.fingerprint)
        .bind(contact.first_seen.to_rfc3339())
        .bind(contact.last_seen.to_rfc3339())
        .bind(contact.verified as i64)
        .execute(&self.pool)
        .await
        .context("upsert contact")?;
        Ok(())
    }

    // -- Messages --

    /// Persist a new message.
    pub async fn save_message(&self, msg: &Message) -> Result<()> {
        sqlx::query(
            "INSERT INTO messages (id, peer_id, direction, body, is_encrypted, created_at, read_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(msg.id.to_string())
        .bind(&msg.peer_id[..])
        .bind(match msg.direction {
            Direction::Outgoing => "outgoing",
            Direction::Incoming => "incoming",
        })
        .bind(&msg.body)
        .bind(msg.is_encrypted as i64)
        .bind(msg.created_at.to_rfc3339())
        .bind(msg.read_at.map(|d| d.to_rfc3339()))
        .execute(&self.pool)
        .await
        .context("save message")?;
        Ok(())
    }

    /// Load message history for a peer, newest first.
    pub async fn get_messages(
        &self,
        peer_id: &[u8; 32],
        limit: i64,
    ) -> Result<Vec<Message>> {
        let rows = sqlx::query_as::<_, MessageRow>(
            "SELECT * FROM messages WHERE peer_id = ?1 ORDER BY created_at DESC LIMIT ?2",
        )
        .bind(&peer_id[..])
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("get messages")?;

        Ok(rows
            .into_iter()
            .rev()
            .map(Message::from_row)
            .collect())
    }

    /// Mark a message as read.
    pub async fn mark_read(&self, msg_id: &Uuid) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE messages SET read_at = ?1 WHERE id = ?2")
            .bind(&now)
            .bind(msg_id.to_string())
            .execute(&self.pool)
            .await
            .context("mark message read")?;
        Ok(())
    }

    // -- Sessions --

    /// Record a new session.
    pub async fn create_session(&self, session: &Session) -> Result<()> {
        sqlx::query(
            "INSERT INTO sessions (id, peer_id, state, created_at, handshake_hash)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(session.id.to_string())
        .bind(&session.peer_id[..])
        .bind(session.state.as_str())
        .bind(session.created_at.to_rfc3339())
        .bind(session.handshake_hash.as_ref().map(|h| &h[..]))
        .execute(&self.pool)
        .await
        .context("create session")?;
        Ok(())
    }

    /// Update session state.
    pub async fn update_session_state(&self, id: &Uuid, state: &SessionState) -> Result<()> {
        sqlx::query("UPDATE sessions SET state = ?1 WHERE id = ?2")
            .bind(state.as_str())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .context("update session state")?;
        Ok(())
    }
}

// -- Contact model --

/// A known peer contact.
#[derive(Debug, Clone)]
pub struct Contact {
    /// Our internal id (UUID).
    pub id: Uuid,
    /// Peer's 32-byte public key (NodeID).
    pub peer_id: [u8; 32],
    /// Human-readable label (nickname).
    pub label: String,
    /// Hex-encoded fingerprint for verification.
    pub fingerprint: String,
    /// When we first saw this peer.
    pub first_seen: DateTime<Utc>,
    /// When we last communicated with this peer.
    pub last_seen: DateTime<Utc>,
    /// Whether we've verified this peer's fingerprint out-of-band.
    pub verified: bool,
}

impl Contact {
    fn from_row(r: ContactRow) -> Self {
        let mut peer_id = [0u8; 32];
        if r.peer_id.len() >= 32 {
            peer_id.copy_from_slice(&r.peer_id[..32]);
        }
        Self {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            peer_id,
            label: r.label,
            fingerprint: r.fingerprint,
            first_seen: r.first_seen.parse().unwrap_or_else(|_| Utc::now()),
            last_seen: r.last_seen.parse().unwrap_or_else(|_| Utc::now()),
            verified: r.verified != 0,
        }
    }
}

#[derive(FromRow)]
struct ContactRow {
    id: String,
    peer_id: Vec<u8>,
    label: String,
    fingerprint: String,
    first_seen: String,
    last_seen: String,
    verified: i64,
}

// -- Message model --

/// Direction of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We sent this message.
    Outgoing,
    /// We received this message.
    Incoming,
}

/// A chat message.
#[derive(Debug, Clone)]
pub struct Message {
    /// Unique id (UUIDv4).
    pub id: Uuid,
    /// Peer's 32-byte public key (NodeID).
    pub peer_id: [u8; 32],
    /// Which direction.
    pub direction: Direction,
    /// Plaintext body (decrypted at read time).
    pub body: String,
    /// Whether the stored body was encrypted at rest.
    pub is_encrypted: bool,
    /// When the message was created (sender's timestamp).
    pub created_at: DateTime<Utc>,
    /// When the message was read by the local user.
    pub read_at: Option<DateTime<Utc>>,
}

impl Message {
    fn from_row(r: MessageRow) -> Self {
        let mut peer_id = [0u8; 32];
        if r.peer_id.len() >= 32 {
            peer_id.copy_from_slice(&r.peer_id[..32]);
        }
        Self {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            peer_id,
            direction: match r.direction.as_str() {
                "incoming" => Direction::Incoming,
                _ => Direction::Outgoing,
            },
            body: r.body,
            is_encrypted: r.is_encrypted != 0,
            created_at: r.created_at.parse().unwrap_or_else(|_| Utc::now()),
            read_at: r.read_at.and_then(|s| s.parse().ok()),
        }
    }
}

#[derive(FromRow)]
struct MessageRow {
    id: String,
    peer_id: Vec<u8>,
    direction: String,
    body: String,
    is_encrypted: i64,
    created_at: String,
    read_at: Option<String>,
}

// -- Session model --

/// State of a chat session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Handshake in progress.
    Handshaking,
    /// Session active (encrypted channel open).
    Active,
    /// Session closed cleanly.
    Closed,
    /// Session terminated with error.
    Error,
}

impl SessionState {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Handshaking => "handshaking",
            Self::Active => "active",
            Self::Closed => "closed",
            Self::Error => "error",
        }
    }
}

/// A recorded chat session.
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session id.
    pub id: Uuid,
    /// Peer's NodeID.
    pub peer_id: [u8; 32],
    /// Current state.
    pub state: SessionState,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// Noise handshake hash (session identifier).
    pub handshake_hash: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};

    static DB_COUNTER: AtomicU16 = AtomicU16::new(0);

    async fn test_store() -> Store {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("p2pchat-test-{n}"));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("test.db");
        Store::open(&path).await.unwrap()
    }

    #[tokio::test]
    async fn create_and_list_contacts() {
        let store = test_store().await;
        let contact = Contact {
            id: Uuid::new_v4(),
            peer_id: [1u8; 32],
            label: "test-peer".into(),
            fingerprint: hex::encode([1u8; 32]),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            verified: true,
        };
        store.upsert_contact(&contact).await.unwrap();
        let contacts = store.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].peer_id, [1u8; 32]);
    }

    #[tokio::test]
    async fn save_and_load_messages() {
        let store = test_store().await;
        let msg = Message {
            id: Uuid::new_v4(),
            peer_id: [1u8; 32],
            direction: Direction::Outgoing,
            body: "hello".into(),
            is_encrypted: true,
            created_at: Utc::now(),
            read_at: None,
        };
        store.save_message(&msg).await.unwrap();
        let msgs = store.get_messages(&[1u8; 32], 100).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "hello");
    }

    #[tokio::test]
    async fn contact_upsert_updates_existing() {
        let store = test_store().await;
        let contact = Contact {
            id: Uuid::new_v4(),
            peer_id: [1u8; 32],
            label: "original".into(),
            fingerprint: "abc".into(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            verified: false,
        };
        store.upsert_contact(&contact).await.unwrap();

        let updated = Contact {
            id: contact.id,
            peer_id: [1u8; 32],
            label: "updated".into(),
            fingerprint: "def".into(),
            first_seen: contact.first_seen,
            last_seen: Utc::now(),
            verified: true,
        };
        store.upsert_contact(&updated).await.unwrap();

        let contacts = store.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].label, "updated");
        assert_eq!(contacts[0].fingerprint, "def");
        assert!(contacts[0].verified);
    }

    #[tokio::test]
    async fn list_contacts_empty_when_no_contacts() {
        let store = test_store().await;
        let contacts = store.list_contacts().await.unwrap();
        assert!(contacts.is_empty());
    }

    #[tokio::test]
    async fn messages_ordered_newest_first() {
        let store = test_store().await;
        let peer_id = [1u8; 32];

        let msg1 = Message {
            id: Uuid::new_v4(),
            peer_id,
            direction: Direction::Outgoing,
            body: "first".into(),
            is_encrypted: true,
            created_at: Utc::now(),
            read_at: None,
        };
        let msg2 = Message {
            id: Uuid::new_v4(),
            peer_id,
            direction: Direction::Outgoing,
            body: "second".into(),
            is_encrypted: true,
            created_at: Utc::now() + chrono::Duration::seconds(1),
            read_at: None,
        };
        store.save_message(&msg1).await.unwrap();
        store.save_message(&msg2).await.unwrap();

        let msgs = store.get_messages(&peer_id, 100).await.unwrap();
        assert_eq!(msgs.len(), 2);
        // get_messages returns in ORDER BY created_at DESC then reversed for oldest-first
        assert_eq!(msgs[0].body, "first");
        assert_eq!(msgs[1].body, "second");
    }

    #[tokio::test]
    async fn messages_respect_limit() {
        let store = test_store().await;
        let peer_id = [1u8; 32];
        for i in 0..10 {
            let msg = Message {
                id: Uuid::new_v4(),
                peer_id,
                direction: Direction::Incoming,
                body: format!("msg {i}"),
                is_encrypted: true,
                created_at: Utc::now(),
                read_at: None,
            };
            store.save_message(&msg).await.unwrap();
        }
        let msgs = store.get_messages(&peer_id, 3).await.unwrap();
        assert_eq!(msgs.len(), 3);
    }

    #[tokio::test]
    async fn messages_isolated_by_peer() {
        let store = test_store().await;
        let msg_a = Message {
            id: Uuid::new_v4(),
            peer_id: [1u8; 32],
            direction: Direction::Outgoing,
            body: "for peer A".into(),
            is_encrypted: true,
            created_at: Utc::now(),
            read_at: None,
        };
        let msg_b = Message {
            id: Uuid::new_v4(),
            peer_id: [2u8; 32],
            direction: Direction::Incoming,
            body: "for peer B".into(),
            is_encrypted: true,
            created_at: Utc::now(),
            read_at: None,
        };
        store.save_message(&msg_a).await.unwrap();
        store.save_message(&msg_b).await.unwrap();

        let msgs_a = store.get_messages(&[1u8; 32], 100).await.unwrap();
        assert_eq!(msgs_a.len(), 1);
        assert_eq!(msgs_a[0].body, "for peer A");

        let msgs_b = store.get_messages(&[2u8; 32], 100).await.unwrap();
        assert_eq!(msgs_b.len(), 1);
        assert_eq!(msgs_b[0].body, "for peer B");
    }

    #[tokio::test]
    async fn mark_read_updates_message() {
        let store = test_store().await;
        let msg = Message {
            id: Uuid::new_v4(),
            peer_id: [1u8; 32],
            direction: Direction::Incoming,
            body: "read me".into(),
            is_encrypted: true,
            created_at: Utc::now(),
            read_at: None,
        };
        store.save_message(&msg).await.unwrap();
        assert!(msg.read_at.is_none());

        store.mark_read(&msg.id).await.unwrap();
        let msgs = store.get_messages(&[1u8; 32], 100).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].read_at.is_some());
    }

    #[tokio::test]
    async fn create_and_update_session() {
        let store = test_store().await;
        let session = Session {
            id: Uuid::new_v4(),
            peer_id: [1u8; 32],
            state: SessionState::Handshaking,
            created_at: Utc::now(),
            handshake_hash: Some([0xABu8; 32]),
        };
        store.create_session(&session).await.unwrap();

        store
            .update_session_state(&session.id, &SessionState::Active)
            .await
            .unwrap();

        store
            .update_session_state(&session.id, &SessionState::Closed)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn session_state_as_str() {
        assert_eq!(SessionState::Handshaking.as_str(), "handshaking");
        assert_eq!(SessionState::Active.as_str(), "active");
        assert_eq!(SessionState::Closed.as_str(), "closed");
        assert_eq!(SessionState::Error.as_str(), "error");
    }

    #[tokio::test]
    async fn save_message_with_read_at() {
        let store = test_store().await;
        let msg = Message {
            id: Uuid::new_v4(),
            peer_id: [1u8; 32],
            direction: Direction::Outgoing,
            body: "already read".into(),
            is_encrypted: false,
            created_at: Utc::now(),
            read_at: Some(Utc::now()),
        };
        store.save_message(&msg).await.unwrap();
        let msgs = store.get_messages(&[1u8; 32], 100).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "already read");
        assert_eq!(msgs[0].direction, Direction::Outgoing);
        assert!(!msgs[0].is_encrypted);
        assert!(msgs[0].read_at.is_some());
    }
}
