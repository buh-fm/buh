//! Abstract service-credit value types for the settlement seam (`doc/design.md` §8.5).
//!
//! **Critical invariant:** nothing here names a chain, a fiat currency, or a redeemable
//! monetary amount. A [`Credit`] is a claim on *service from the network* — "N byte-hours of
//! mailbox / N MB of egress" — never a claim on a pot of value. The platform holds nothing,
//! denominates nothing, and redeems nothing for fiat. The concrete chain (ETH/SOL) lives only
//! inside a `SettlementBackend` implementation, never above the trait. If a chain identifier
//! ever appears in this module, the "design for both, build one" seam is broken.
//!
//! These are stubs sufficient for the trait to compile against a stub backend (Phase 7); the
//! real edge-settlement / fair-exchange design is the explicit open problem (`§9`).

use serde::{Deserialize, Serialize};

/// A claim on a quantity of relay service, denominated in abstract service units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credit {
    /// Service units (e.g. byte-hours of mailbox, or MB of egress). Not money.
    pub units: u64,
}

/// Instructions for a consumer to obtain entitlement at the edge, on whatever rail they choose.
///
/// Deliberately opaque above the trait: the string is whatever the backend needs (an address,
/// a memo, a payment URI). The core never parses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositInstructions {
    /// Backend-defined, chain-agnostic deposit reference.
    pub reference: String,
}

/// Proof that a consumer completed an edge deposit, presented to claim entitlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositProof {
    /// Backend-defined, chain-agnostic proof material.
    pub reference: String,
}

/// A destination for a node-runner payout at the edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payout {
    /// Backend-defined, chain-agnostic destination reference.
    pub destination: String,
}

/// An opaque reference to a settled edge transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRef {
    /// Backend-defined transaction reference.
    pub reference: String,
}

/// A backend attestation that it can honour outstanding entitlement (non-custodial: this
/// attests capacity to settle peer-to-peer at the edge, not a held reserve).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencyProof {
    /// Backend-defined attestation material.
    pub attestation: String,
}
