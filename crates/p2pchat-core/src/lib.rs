//! p2pchat-core: identity, transport, crypto, storage, message protocol.

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

/// Package version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-facing configuration (paths, defaults).
pub mod config {
    use std::path::PathBuf;

    /// Root directory for p2pchat state (`identity.enc`, future message db, etc.).
    /// Honors `$XDG_CONFIG_HOME` on Linux; falls back to `~/.config/p2pchat`.
    pub fn config_dir() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("p2pchat");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".config").join("p2pchat");
        }
        PathBuf::from(".p2pchat")
    }

    /// Path to the encrypted identity file.
    pub fn identity_path() -> PathBuf {
        config_dir().join("identity.enc")
    }

    /// Path to the chat database.
    pub fn db_path() -> PathBuf {
        config_dir().join("chat.db")
    }
}

/// Initialize global tracing subscriber. Idempotent.
pub fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_target(false))
        .try_init();
}

/// Long-term identity (Ed25519 keypair, encrypted at rest).
pub mod identity;

/// iroh-based transport (QUIC over public relay with NAT traversal).
pub mod transport;

/// Wire format: length-prefixed frames + message types.
pub mod message;

/// Noise XX handshake wrapper using the `snow` crate.
pub mod crypto;

/// Double Ratchet per-message encryption.
pub mod ratchet;

/// SQLite-backed persistence for messages, contacts, and sessions.
pub mod storage;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_is_absolute_or_relative_fallback() {
        let d = config::config_dir();
        // Either we got a real path or the relative fallback; either way it's non-empty.
        assert!(!d.as_os_str().is_empty());
    }

    #[test]
    fn version_is_nonempty() {
        assert!(!VERSION.is_empty());
    }
}
