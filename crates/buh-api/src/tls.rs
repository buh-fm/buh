//! Decentralised PQ-mTLS for node ingress and node↔node calls (`doc/design.md` §5.1).
//!
//! This is the per-node-CA deviation made concrete. There is **no central PKI and no step-ca**:
//!
//! - **Key exchange is post-quantum.** The [`CryptoProvider`] offers **X25519MLKEM768** first, so
//!   a handshake recorded today is not harvest-now-decrypt-later material.
//! - **Trust is per-CA, pinned by fingerprint — not a shared root.** Each node is its own CA
//!   ([`buh_core::NodePki`]); a peer is accepted only if the CA at the tail of its presented chain
//!   has a fingerprint in this node's [`TrustStore`], *and* its leaf cryptographically chains to
//!   that CA. Distrusting a CA refuses it on the very next handshake.
//! - **Leaves auto-rotate in process.** The server reads the current leaf through a
//!   [`RotatingResolver`]; a timer swaps a freshly issued leaf in without dropping connections.
//!
//! The custom verifiers ([`PinnedClientCertVerifier`], [`PinnedServerCertVerifier`]) are the heart
//! of the model. They are synchronous (as rustls requires), so they read a cached snapshot of the
//! trust set rather than touching the database on the handshake path.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, RwLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};
use x509_parser::prelude::*;

use buh_core::{CoreError, NodeLeaf, NodePki};
use buh_data::fingerprint;

/// A live, shareable snapshot of the peer-CA fingerprints this node trusts.
///
/// Cloned into the certificate verifiers; the daemon swaps its contents (via [`Self::replace`])
/// whenever the operator changes trust, so the verifiers see the change without a restart.
#[derive(Clone, Default)]
pub struct TrustStore {
    inner: Arc<RwLock<HashSet<String>>>,
}

impl fmt::Debug for TrustStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.inner.read().map(|s| s.len()).unwrap_or(0);
        write!(f, "TrustStore({n} pinned)")
    }
}

impl TrustStore {
    /// An empty trust store (trusts nobody until told to).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from an initial set of (already-normalised) CA fingerprints.
    #[must_use]
    pub fn from_fingerprints(fps: impl IntoIterator<Item = String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(fps.into_iter().collect())),
        }
    }

    /// Atomically replace the whole trusted set (used to refresh from the registry).
    pub fn replace(&self, fps: impl IntoIterator<Item = String>) {
        let mut g = self.inner.write().expect("trust store poisoned");
        *g = fps.into_iter().collect();
    }

    /// Whether a CA fingerprint is currently trusted.
    #[must_use]
    pub fn contains(&self, ca_fingerprint: &str) -> bool {
        self.inner
            .read()
            .expect("trust store poisoned")
            .contains(ca_fingerprint)
    }
}

/// Build the post-quantum [`CryptoProvider`]: aws-lc-rs with **X25519MLKEM768 preferred**, then
/// classical X25519 as a fallback for peers that have not yet enabled the hybrid group.
#[must_use]
pub fn pq_provider() -> Arc<CryptoProvider> {
    use rustls::crypto::aws_lc_rs;
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::X25519MLKEM768,
        aws_lc_rs::kx_group::X25519,
    ];
    Arc::new(provider)
}

/// Verify a presented chain `[leaf, …, ca]` against the pinned trust set: the CA (chain tail) must
/// be trusted by fingerprint, must be a self-consistent CA, and the leaf must chain to it and be
/// currently valid. This is the single trust decision shared by both verifiers.
fn verify_pinned_chain(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
    trust: &TrustStore,
) -> Result<(), Error> {
    // Our nodes always present [leaf, CA]; the CA is the tail.
    let ca_der = intermediates
        .last()
        .ok_or_else(|| Error::General("peer presented no issuing CA".into()))?;

    // 1. Pin: the CA fingerprint must be one we were told to trust.
    if !trust.contains(&fingerprint(ca_der)) {
        return Err(Error::General("peer CA is not trusted (unpinned)".into()));
    }

    // 2. Parse both certificates.
    let (_, ca) = X509Certificate::from_der(ca_der)
        .map_err(|_| Error::General("malformed CA cert".into()))?;
    let (_, leaf) = X509Certificate::from_der(end_entity)
        .map_err(|_| Error::General("malformed leaf cert".into()))?;

    // 3. The pinned cert must actually be a CA, self-signed (it is a root).
    match ca.basic_constraints() {
        Ok(Some(bc)) if bc.value.ca => {}
        _ => return Err(Error::General("pinned cert is not a CA".into())),
    }
    ca.verify_signature(None)
        .map_err(|_| Error::General("CA self-signature invalid".into()))?;

    // 4. The leaf must be signed by that CA.
    leaf.verify_signature(Some(ca.public_key()))
        .map_err(|_| Error::General("leaf does not chain to pinned CA".into()))?;

    // 5. Both must be temporally valid.
    let now_secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    check_validity(&leaf, now_secs, "leaf")?;
    check_validity(&ca, now_secs, "CA")?;

    Ok(())
}

/// Reject a certificate whose validity window does not contain `now_secs`.
fn check_validity(cert: &X509Certificate<'_>, now_secs: i64, what: &str) -> Result<(), Error> {
    let v = cert.validity();
    if now_secs < v.not_before.timestamp() {
        return Err(Error::General(format!("{what} not yet valid")));
    }
    if now_secs > v.not_after.timestamp() {
        return Err(Error::General(format!("{what} expired")));
    }
    Ok(())
}

/// Server-side verifier: accept a client whose CA we pin and whose leaf chains to it.
#[derive(Debug)]
pub struct PinnedClientCertVerifier {
    provider: Arc<CryptoProvider>,
    trust: TrustStore,
    /// We give no root hints (each node has a single leaf and sends it unprompted).
    no_hints: Vec<DistinguishedName>,
}

impl PinnedClientCertVerifier {
    #[must_use]
    fn new(provider: Arc<CryptoProvider>, trust: TrustStore) -> Self {
        Self {
            provider,
            trust,
            no_hints: Vec::new(),
        }
    }
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.no_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        verify_pinned_chain(end_entity, intermediates, now, &self.trust)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Client-side verifier: accept a server whose CA we pin and whose leaf chains to it. Trust is by
/// CA fingerprint, so the TLS server name is irrelevant and not checked.
#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    provider: Arc<CryptoProvider>,
    trust: TrustStore,
}

impl PinnedServerCertVerifier {
    #[must_use]
    fn new(provider: Arc<CryptoProvider>, trust: TrustStore) -> Self {
        Self { provider, trust }
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        verify_pinned_chain(end_entity, intermediates, now, &self.trust)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A server cert resolver whose current leaf can be swapped atomically by the rotation timer.
#[derive(Debug)]
pub struct RotatingResolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl RotatingResolver {
    fn new(initial: Arc<CertifiedKey>) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    fn store(&self, next: Arc<CertifiedKey>) {
        *self.current.write().expect("resolver poisoned") = next;
    }
}

impl ResolvesServerCert for RotatingResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().expect("resolver poisoned").clone())
    }
}

/// Turn a freshly issued [`NodeLeaf`] into a rustls [`CertifiedKey`].
fn certified_key(
    provider: &CryptoProvider,
    leaf: &NodeLeaf,
) -> Result<Arc<CertifiedKey>, CoreError> {
    let certs: Vec<CertificateDer<'static>> = leaf
        .chain_der
        .iter()
        .cloned()
        .map(CertificateDer::from)
        .collect();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.private_key_der.clone()));
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .map_err(tls("load leaf key"))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// The assembled PQ-mTLS material for one node: the PQ provider, its trust snapshot, the rotating
/// server leaf, and the [`NodePki`] used to keep issuing leaves.
#[derive(Clone)]
pub struct NodeTls {
    provider: Arc<CryptoProvider>,
    trust: TrustStore,
    resolver: Arc<RotatingResolver>,
    pki: Arc<dyn NodePki>,
}

impl NodeTls {
    /// Assemble from this node's [`NodePki`] and a trust snapshot, issuing the first leaf.
    pub fn new(pki: Arc<dyn NodePki>, trust: TrustStore) -> Result<Self, CoreError> {
        let provider = pq_provider();
        let leaf = pki.issue_leaf()?;
        let resolver = Arc::new(RotatingResolver::new(certified_key(&provider, &leaf)?));
        Ok(Self {
            provider,
            trust,
            resolver,
            pki,
        })
    }

    /// The trust snapshot (so the daemon can refresh it from the registry).
    #[must_use]
    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    /// Issue a fresh leaf and swap it into the live resolver. Returns its expiry (epoch ms) so the
    /// caller can schedule the next rotation. Existing connections keep their handshake leaf.
    pub fn rotate_leaf(&self) -> Result<i64, CoreError> {
        let leaf = self.pki.issue_leaf()?;
        let next = certified_key(&self.provider, &leaf)?;
        self.resolver.store(next);
        Ok(leaf.not_after_ms)
    }

    /// A TLS 1.3-only server config that requires a client cert (mutual auth), pins the client CA,
    /// and serves the rotating leaf.
    pub fn server_config(&self) -> Result<ServerConfig, CoreError> {
        let verifier = Arc::new(PinnedClientCertVerifier::new(
            self.provider.clone(),
            self.trust.clone(),
        ));
        ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls("server protocol versions"))
            .map(|b| {
                b.with_client_cert_verifier(verifier)
                    .with_cert_resolver(self.resolver.clone())
            })
    }

    /// A TLS 1.3-only client config that presents a freshly issued leaf and pins the server CA.
    /// Used for node↔node calls and by the hermetic handshake test.
    pub fn client_config(&self) -> Result<ClientConfig, CoreError> {
        let leaf = self.pki.issue_leaf()?;
        let certs: Vec<CertificateDer<'static>> = leaf
            .chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.private_key_der.clone()));
        let verifier = Arc::new(PinnedServerCertVerifier::new(
            self.provider.clone(),
            self.trust.clone(),
        ));
        ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls("client protocol versions"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certs, key)
            .map_err(tls("client auth cert"))
    }
}

/// Map a rustls error into a [`CoreError`].
fn tls(ctx: &'static str) -> impl Fn(Error) -> CoreError {
    move |e| CoreError::Internal(format!("tls: {ctx}: {e}"))
}
