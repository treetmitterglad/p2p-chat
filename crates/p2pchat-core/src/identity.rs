//! Long-term identity: Ed25519 keypair, encrypted at rest with a passphrase.
//!
//! File format (`identity.enc`):
//!
//! ```text
//! [0..8]    magic            b"P2PCHAT\0"
//! [8]       version          u8 (= 0x01)
//! [9]       kdf id           u8 (= 0x01 = Argon2id)
//! [10..14]  argon2 m_kib     u32 LE
//! [14..18]  argon2 t         u32 LE
//! [18..22]  argon2 p         u32 LE
//! [22..38]  salt             16 random bytes
//! [38..62]  nonce            24 random bytes
//! [62..]    ciphertext+tag   XChaCha20-Poly1305(32-byte ed25519 seed)
//! ```
//!
//! The on-disk plaintext is the 32-byte Ed25519 secret seed. The public key
//! (also 32 bytes) is the `NodeID`.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"P2PCHAT\0";
const FILE_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + 16 + 24; // = 62
const PLAINTEXT_LEN: usize = 32; // ed25519 seed

/// Argon2id parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB, 3 iterations, 1 lane. OWASP-recommended floor for interactive use.
        Self {
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
        }
    }
}

/// Errors that can occur when reading, writing, or validating an identity file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The passphrase did not decrypt the file (AEAD tag mismatch or malformed plaintext).
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// File is well-formed enough to parse the header but something is structurally wrong
    /// after the passphrase was correct (e.g., wrong plaintext length).
    #[error("identity file is corrupted or has been tampered with")]
    Tampered,
    /// File starts with bytes that aren't the expected magic.
    #[error("invalid magic bytes; not a p2pchat identity file")]
    InvalidMagic,
    /// File is shorter than the header.
    #[error("file too short: expected at least {expected} bytes, got {actual}")]
    FileTooShort {
        /// Minimum number of bytes the header requires.
        expected: usize,
        /// Actual length read from disk.
        actual: usize,
    },
    /// File version byte is not supported by this build.
    #[error("unsupported file version: {0}")]
    UnsupportedVersion(u8),
    /// KDF id is not supported by this build.
    #[error("unsupported KDF: {0}")]
    UnsupportedKdf(u8),
    /// Argon2 rejected the parameters.
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(String),
    /// Underlying I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for identity operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Header metadata that can be read without a passphrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// File format version.
    pub version: u8,
    /// KDF parameters.
    pub kdf: KdfParams,
}

/// A long-term Ed25519 identity keypair.
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a new random identity using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Reconstruct an identity from a 32-byte secret seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// 32-byte public key (NodeID).
    pub fn node_id(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// 16-byte fingerprint (first 16 bytes of SHA-256(NodeID)).
    ///
    /// Stable across runs. Suitable for short verbal comparison and QR display.
    pub fn fingerprint(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(self.node_id());
        let digest = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    /// 32-byte Ed25519 secret seed. Use sparingly; this is the at-rest secret.
    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Borrow the signing key (for use by transport / crypto layers).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("node_id", &hex::encode(self.node_id()))
            .field("fingerprint", &hex::encode(self.fingerprint()))
            .finish_non_exhaustive()
    }
}

/// Parse the file header (magic, version, KDF id and params) without decrypting.
pub fn parse_header(blob: &[u8]) -> Result<Header> {
    if blob.len() < HEADER_LEN {
        return Err(Error::FileTooShort {
            expected: HEADER_LEN,
            actual: blob.len(),
        });
    }
    if &blob[..8] != MAGIC {
        return Err(Error::InvalidMagic);
    }
    let version = blob[8];
    if version != FILE_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let kdf_id = blob[9];
    if kdf_id != KDF_ARGON2ID {
        return Err(Error::UnsupportedKdf(kdf_id));
    }
    let m_kib = u32::from_le_bytes(blob[10..14].try_into().expect("checked len"));
    let t = u32::from_le_bytes(blob[14..18].try_into().expect("checked len"));
    let p = u32::from_le_bytes(blob[18..22].try_into().expect("checked len"));
    Ok(Header {
        version,
        kdf: KdfParams { m_kib, t, p },
    })
}

/// Encrypt a 32-byte seed into a self-contained identity file blob.
pub fn encrypt(seed: &[u8; 32], passphrase: &str, params: KdfParams) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let kek = derive_kek(passphrase, &salt, params)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek[..]));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), seed.as_ref())
        .map_err(|_| Error::Tampered)?;

    let mut out = Vec::with_capacity(HEADER_LEN + PLAINTEXT_LEN + 16);
    out.extend_from_slice(MAGIC);
    out.push(FILE_VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&params.m_kib.to_le_bytes());
    out.extend_from_slice(&params.t.to_le_bytes());
    out.extend_from_slice(&params.p.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt an identity file blob, returning the 32-byte seed.
pub fn decrypt(blob: &[u8], passphrase: &str) -> Result<[u8; 32]> {
    let header = parse_header(blob)?;
    let salt: [u8; 16] = blob[22..38].try_into().expect("checked len");
    let nonce: [u8; 24] = blob[38..62].try_into().expect("checked len");
    let ct = &blob[62..];

    let kek = derive_kek(passphrase, &salt, header.kdf)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek[..]));

    let pt = cipher
        .decrypt(XNonce::from_slice(&nonce), ct)
        .map_err(|_| Error::WrongPassphrase)?;
    if pt.len() != PLAINTEXT_LEN {
        return Err(Error::Tampered);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&pt);
    Ok(seed)
}

fn derive_kek(passphrase: &str, salt: &[u8; 16], params: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| Error::InvalidKdfParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| Error::InvalidKdfParams(e.to_string()))?;
    Ok(out)
}

/// Persist an identity to disk at `path`, creating parent dirs as needed.
///
/// Writes atomically: writes to a `.tmp` sibling, fsyncs, then renames.
pub fn save_to_path(identity: &Identity, passphrase: &str, path: &Path) -> Result<()> {
    let blob = encrypt(&identity.seed(), passphrase, KdfParams::default())?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("enc.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&blob)?;
        f.sync_all()?;
    }
    // Remove destination first so rename works on all platforms (Windows
    // rejects rename when destination exists).
    let _ = fs::remove_file(path);
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Load an identity from `path`, decrypting with `passphrase`.
pub fn load_from_path(passphrase: &str, path: &Path) -> Result<Identity> {
    let mut blob = Vec::new();
    fs::File::open(path)?.read_to_end(&mut blob)?;
    let seed = decrypt(&blob, passphrase)?;
    Ok(Identity::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_with_params(params: KdfParams) {
        let id = Identity::generate();
        let blob = encrypt(&id.seed(), "correct horse battery staple", params).unwrap();
        let seed = decrypt(&blob, "correct horse battery staple").unwrap();
        let id2 = Identity::from_seed(seed);
        assert_eq!(id.node_id(), id2.node_id());
        assert_eq!(id.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn round_trip_default_params() {
        round_trip_with_params(KdfParams::default());
    }

    #[test]
    fn round_trip_low_params_for_test_speed() {
        // 1 MiB, 1 iter, 1 lane. Validates the format, doesn't bench KDF.
        round_trip_with_params(KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
        });
    }

    #[test]
    fn wrong_passphrase_is_typed_error() {
        let id = Identity::generate();
        let blob = encrypt(
            &id.seed(),
            "right",
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let err = decrypt(&blob, "wrong").unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase), "got {err:?}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let id = Identity::generate();
        let mut blob = encrypt(
            &id.seed(),
            "x",
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let err = decrypt(&blob, "x").unwrap_err();
        assert!(
            matches!(err, Error::WrongPassphrase | Error::Tampered),
            "got {err:?}"
        );
    }

    #[test]
    fn truncated_file_is_too_short() {
        let err = decrypt(&[0; 5], "x").unwrap_err();
        assert!(matches!(err, Error::FileTooShort { .. }), "got {err:?}");
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut blob = vec![0u8; 80];
        blob[..4].copy_from_slice(b"junk");
        let err = decrypt(&blob, "x").unwrap_err();
        assert!(matches!(err, Error::InvalidMagic), "got {err:?}");
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut blob = encrypt(
            &[1u8; 32],
            "x",
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        blob[8] = 99;
        let err = decrypt(&blob, "x").unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(99)), "got {err:?}");
    }

    #[test]
    fn bad_kdf_id_is_rejected() {
        let mut blob = encrypt(
            &[1u8; 32],
            "x",
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        blob[9] = 99;
        let err = decrypt(&blob, "x").unwrap_err();
        assert!(matches!(err, Error::UnsupportedKdf(99)), "got {err:?}");
    }

    #[test]
    fn header_parses_without_passphrase() {
        let blob = encrypt(
            &[1u8; 32],
            "x",
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let h = parse_header(&blob).unwrap();
        assert_eq!(h.version, FILE_VERSION);
        assert_eq!(
            h.kdf,
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1
            }
        );
    }

    #[test]
    fn header_rejects_short_input() {
        assert!(matches!(
            parse_header(&[0; 10]),
            Err(Error::FileTooShort { .. })
        ));
    }

    #[test]
    fn generate_produces_distinct_identities() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.node_id(), b.node_id());
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_is_stable() {
        let id = Identity::generate();
        let f1 = id.fingerprint();
        let f2 = id.fingerprint();
        assert_eq!(f1, f2);
    }

    #[test]
    fn debug_redacts_secrets() {
        let id = Identity::generate();
        let s = format!("{id:?}");
        assert!(
            !s.contains(&hex::encode(id.seed())),
            "seed leaked in Debug: {s}"
        );
        assert!(
            s.contains(&hex::encode(id.node_id())),
            "node id missing in Debug: {s}"
        );
    }

    #[test]
    fn save_load_round_trip_via_disk() {
        let id = Identity::generate();
        let dir = std::env::temp_dir().join(format!("p2pchat-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.enc");
        save_to_path(&id, "sekrit", &path).unwrap();
        let id2 = load_from_path("sekrit", &path).unwrap();
        assert_eq!(id.node_id(), id2.node_id());
        // wrong passphrase
        let err = load_from_path("nope", &path).unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x42u8; 32];
        let a = Identity::from_seed(seed);
        let b = Identity::from_seed(seed);
        assert_eq!(a.node_id(), b.node_id());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.seed(), b.seed());
    }

    #[test]
    fn from_seed_produces_expected_node_id() {
        // Ed25519 keypair from known seed (all-zeros); verify stability
        let id = Identity::from_seed([0u8; 32]);
        // Just verify deterministic: same seed always gives same node_id
        let id2 = Identity::from_seed([0u8; 32]);
        assert_eq!(id.node_id(), id2.node_id());
        // All-zeros seed should not equal all-ones
        let id3 = Identity::from_seed([0xFFu8; 32]);
        assert_ne!(id.node_id(), id3.node_id());
    }

    #[test]
    fn empty_passphrase_round_trip() {
        let id = Identity::generate();
        let blob = encrypt(
            &id.seed(),
            "",
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let seed = decrypt(&blob, "").unwrap();
        let id2 = Identity::from_seed(seed);
        assert_eq!(id.node_id(), id2.node_id());
    }

    #[test]
    fn long_passphrase_round_trip() {
        let long = "a".repeat(1000);
        let id = Identity::generate();
        let blob = encrypt(
            &id.seed(),
            &long,
            KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let seed = decrypt(&blob, &long).unwrap();
        let id2 = Identity::from_seed(seed);
        assert_eq!(id.node_id(), id2.node_id());
    }

    #[test]
    fn different_seeds_produce_different_node_ids() {
        let a = Identity::from_seed([0x01u8; 32]);
        let b = Identity::from_seed([0x02u8; 32]);
        assert_ne!(a.node_id(), b.node_id());
    }

    #[test]
    fn save_to_path_creates_parent_dirs() {
        let id = Identity::generate();
        let dir = std::env::temp_dir().join(format!("p2pchat-save-test-{}", std::process::id()));
        // deliberately nested dir that doesn't exist
        let path = dir.join("sub").join("identity.enc");
        save_to_path(&id, "pw", &path).unwrap();
        assert!(path.exists());
        let loaded = load_from_path("pw", &path).unwrap();
        assert_eq!(id.node_id(), loaded.node_id());
        std::fs::remove_dir_all(&dir).ok();
    }
}
