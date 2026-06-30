//! [`NodePki`] implemented with `rcgen`: the decentralised per-node CA (`doc/design.md` §5.1).
//!
//! Each node is its own root of trust — **no central PKI, no step-ca**. On first start a node
//! generates a long-lived CA, persists it under the configurable PKI dir, and thereafter issues
//! its own short-lived TLS leaves which auto-rotate in process. Peers/clients pin the node by its
//! CA fingerprint (lowercase hex SHA-256 of the CA cert DER); the leaf is verified to chain to it.
//!
//! The CA signs with a classical algorithm (ECDSA P-256). That is deliberate: the post-quantum
//! property buh needs at the transport is *confidentiality* against harvest-now-decrypt-later,
//! which is provided by the X25519MLKEM768 key exchange in [`crate`]'s sibling `buh-api` TLS
//! layer. Certificate *signatures* only need to be unforgeable at handshake time, so a classical
//! signature is sufficient and avoids depending on not-yet-standardised PQ certificate formats.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use buh_core::{CoreError, NodeLeaf, NodePki};

/// Filename of the persisted CA certificate (DER — the exact bytes the fingerprint covers).
const CA_CERT_FILE: &str = "ca.cert.der";
/// Filename of the persisted CA private key (PKCS#8 PEM).
const CA_KEY_FILE: &str = "ca.key.pem";
/// Subject/issuer common name stamped on the node CA. Rebuilt identically on load.
const CA_COMMON_NAME: &str = "buh node CA";
/// Subject common name stamped on issued leaves.
const LEAF_COMMON_NAME: &str = "buh node leaf";
/// Backdate leaves slightly to tolerate small clock skew between peers.
const CLOCK_SKEW: Duration = Duration::from_secs(300);

/// A node's own CA plus the parameters needed to keep issuing leaves that chain to it.
///
/// Cheap to clone? No — holds key material; wrap in `Arc` (it implements [`NodePki`]).
pub struct RcgenNodeCa {
    /// The CA key pair (signs every issued leaf).
    ca_key: KeyPair,
    /// A reconstructed CA certificate used only as the *issuer* when signing leaves. Its own DER
    /// is irrelevant — leaves chain to [`Self::ca_der`] cryptographically, by the CA public key.
    ca_issuer: Certificate,
    /// The canonical, persisted CA certificate DER (fingerprint source + chain element).
    ca_der: Vec<u8>,
    /// Lowercase hex SHA-256 of [`Self::ca_der`] — the value clients pin.
    ca_fingerprint: String,
    /// Subject alternative names stamped on issued leaves.
    sans: Vec<String>,
    /// Validity window applied to each issued leaf.
    leaf_ttl: Duration,
}

impl RcgenNodeCa {
    /// Load the node CA from `pki_dir`, generating and persisting a fresh one on first start.
    ///
    /// `sans` are the subject alternative names stamped on issued leaves (hostnames/IPs the node
    /// answers to). `leaf_ttl` is each leaf's validity window; the caller re-issues on a timer
    /// well inside it. Files are written `0600`/`0700` on Unix.
    pub fn load_or_init(
        pki_dir: impl Into<PathBuf>,
        sans: Vec<String>,
        leaf_ttl: Duration,
    ) -> Result<Self, CoreError> {
        let dir = pki_dir.into();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        let (ca_key, ca_der) = if cert_path.exists() && key_path.exists() {
            let key_pem = fs::read_to_string(&key_path).map_err(io("read CA key"))?;
            let ca_key = KeyPair::from_pem(&key_pem).map_err(pki("parse CA key"))?;
            let ca_der = fs::read(&cert_path).map_err(io("read CA cert"))?;
            (ca_key, ca_der)
        } else {
            let ca_key = KeyPair::generate().map_err(pki("generate CA key"))?;
            let ca_cert = ca_params()?
                .self_signed(&ca_key)
                .map_err(pki("self-sign CA"))?;
            let ca_der = ca_cert.der().to_vec();
            persist(&dir, &cert_path, &key_path, &ca_der, &ca_key)?;
            (ca_key, ca_der)
        };

        Self::from_loaded(ca_key, ca_der, sans, leaf_ttl)
    }

    /// Re-key the node CA: back up any existing CA material (to `*.bak`) and generate a fresh CA,
    /// changing the node's pinned fingerprint. Destructive — every peer must re-pin the new
    /// fingerprint. Used by `buh-cli ca rotate`.
    pub fn rekey(
        pki_dir: impl Into<PathBuf>,
        sans: Vec<String>,
        leaf_ttl: Duration,
    ) -> Result<Self, CoreError> {
        let dir = pki_dir.into();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        for path in [&cert_path, &key_path] {
            if path.exists() {
                let bak = path.with_file_name(format!(
                    "{}.bak",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("ca")
                ));
                fs::rename(path, &bak).map_err(io("back up old CA"))?;
            }
        }
        Self::load_or_init(dir, sans, leaf_ttl)
    }

    /// Finish construction from loaded/generated CA material: rebuild the signing issuer and
    /// compute the pinned fingerprint.
    fn from_loaded(
        ca_key: KeyPair,
        ca_der: Vec<u8>,
        sans: Vec<String>,
        leaf_ttl: Duration,
    ) -> Result<Self, CoreError> {
        // Rebuild a CA certificate object to use as the signing issuer. Deterministic params +
        // the same key reproduce the same subject DN and key identifier, so issued leaves chain
        // to the persisted CA DER regardless of this object's own (ignored) serialization.
        let ca_issuer = ca_params()?
            .self_signed(&ca_key)
            .map_err(pki("rebuild CA issuer"))?;
        let ca_fingerprint = fingerprint(&ca_der);

        Ok(Self {
            ca_key,
            ca_issuer,
            ca_der,
            ca_fingerprint,
            sans,
            leaf_ttl,
        })
    }
}

impl NodePki for RcgenNodeCa {
    fn ca_fingerprint(&self) -> &str {
        &self.ca_fingerprint
    }

    fn ca_cert_der(&self) -> &[u8] {
        &self.ca_der
    }

    fn issue_leaf(&self) -> Result<NodeLeaf, CoreError> {
        let leaf_key = KeyPair::generate().map_err(pki("generate leaf key"))?;

        let now = OffsetDateTime::now_utc();
        let not_before = now - self.leaf_ttl_skew();
        let not_after = now + self.leaf_ttl;

        let mut params = CertificateParams::new(self.sans.clone()).map_err(pki("leaf params"))?;
        params.distinguished_name = dn(LEAF_COMMON_NAME);
        params.is_ca = IsCa::NoCa;
        params.not_before = not_before;
        params.not_after = not_after;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // The node is both a TLS server (ingress) and a TLS client (node↔node), so the leaf
        // carries both purposes.
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let leaf = params
            .signed_by(&leaf_key, &self.ca_issuer, &self.ca_key)
            .map_err(pki("sign leaf"))?;

        Ok(NodeLeaf {
            chain_der: vec![leaf.der().to_vec(), self.ca_der.clone()],
            private_key_der: leaf_key.serialize_der(),
            not_after_ms: (not_after.unix_timestamp()) * 1000,
        })
    }
}

impl RcgenNodeCa {
    fn leaf_ttl_skew(&self) -> time::Duration {
        time::Duration::seconds(CLOCK_SKEW.as_secs() as i64)
    }
}

/// Compute the pinned fingerprint of a CA certificate DER: lowercase hex SHA-256, no separators.
#[must_use]
pub fn fingerprint(ca_der: &[u8]) -> String {
    hex::encode(Sha256::digest(ca_der))
}

/// Deterministic parameters for the node CA. Rebuilt identically on every load so the
/// reconstructed issuer matches the persisted certificate.
fn ca_params() -> Result<CertificateParams, CoreError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(pki("CA params"))?;
    params.distinguished_name = dn(CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

/// A distinguished name carrying a single common name.
fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

/// Persist the CA cert (DER) and key (PEM) with restrictive permissions.
fn persist(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    ca_der: &[u8],
    ca_key: &KeyPair,
) -> Result<(), CoreError> {
    fs::create_dir_all(dir).map_err(io("create PKI dir"))?;
    restrict_dir(dir)?;
    fs::write(cert_path, ca_der).map_err(io("write CA cert"))?;
    fs::write(key_path, ca_key.serialize_pem()).map_err(io("write CA key"))?;
    restrict_file(key_path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io("chmod PKI dir"))
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io("chmod CA key"))
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) -> Result<(), CoreError> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), CoreError> {
    Ok(())
}

/// Map an rcgen error into a [`CoreError`].
fn pki(ctx: &'static str) -> impl Fn(rcgen::Error) -> CoreError {
    move |e| CoreError::Internal(format!("pki: {ctx}: {e}"))
}

/// Map an I/O error into a [`CoreError`].
fn io(ctx: &'static str) -> impl Fn(std::io::Error) -> CoreError {
    move |e| CoreError::Internal(format!("pki: {ctx}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca(dir: &Path) -> RcgenNodeCa {
        RcgenNodeCa::load_or_init(
            dir,
            vec!["localhost".to_string()],
            Duration::from_secs(3600),
        )
        .expect("init CA")
    }

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let dir = tempfile::tempdir().unwrap();
        let pki = ca(dir.path());
        assert_eq!(pki.ca_fingerprint().len(), 64);
        assert!(pki.ca_fingerprint().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(pki.ca_fingerprint(), &fingerprint(pki.ca_cert_der()));
    }

    #[test]
    fn fingerprint_is_stable_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let first = ca(dir.path()).ca_fingerprint().to_string();
        // Reloading from disk must reproduce the exact same pinned identity.
        let second = ca(dir.path()).ca_fingerprint().to_string();
        assert_eq!(first, second);
    }

    #[test]
    fn issued_leaf_chains_to_ca_and_carries_chain() {
        let dir = tempfile::tempdir().unwrap();
        let pki = ca(dir.path());
        let leaf = pki.issue_leaf().expect("issue leaf");
        assert_eq!(leaf.chain_der.len(), 2, "leaf + CA");
        assert_eq!(leaf.chain_der[1], pki.ca_cert_der(), "CA is the chain tail");
        assert!(!leaf.private_key_der.is_empty());
        assert!(leaf.not_after_ms > chrono::Utc::now().timestamp_millis());

        // Cryptographically verify the leaf is signed by the CA public key.
        use x509_parser::prelude::*;
        let (_, ca_cert) = X509Certificate::from_der(pki.ca_cert_der()).unwrap();
        let (_, leaf_cert) = X509Certificate::from_der(&leaf.chain_der[0]).unwrap();
        leaf_cert
            .verify_signature(Some(ca_cert.public_key()))
            .expect("leaf chains to CA");
    }

    #[test]
    fn distinct_dirs_have_distinct_cas() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        assert_ne!(ca(a.path()).ca_fingerprint(), ca(b.path()).ca_fingerprint());
    }
}
