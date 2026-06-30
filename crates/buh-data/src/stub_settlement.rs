//! A stub [`SettlementBackend`] (`doc/design.md` §8.5, §13 item 8).
//!
//! Settlement is "design for both, build one": the real edge-settlement / fair-exchange
//! mechanism is the explicit open problem (§9), and the concrete chain (ETH/SOL) must live only
//! *inside* a backend, never above the trait. This stub exists to (a) prove the 4-method seam
//! compiles and round-trips against abstract service [`Credit`]s, and (b) anchor the test that
//! no chain identifier ever leaks above the trait. It hands out canned, chain-agnostic quotes
//! and attestations and refuses to pay out — a node must not pretend to settle real value.

use async_trait::async_trait;

use buh_core::CoreError;
use buh_core::ports::SettlementBackend;
use buh_entities::{Credit, DepositInstructions, DepositProof, Payout, SolvencyProof, TxRef};

/// A non-settling settlement backend: quotes and attests in the abstract, never pays out.
#[derive(Debug, Default, Clone)]
pub struct StubSettlement;

#[async_trait]
impl SettlementBackend for StubSettlement {
    async fn onramp_quote(&self, value: Credit) -> Result<DepositInstructions, CoreError> {
        // Chain-agnostic reference: it names service units, not a rail, an address, or a coin.
        Ok(DepositInstructions {
            reference: format!("stub-onramp:{}-service-units", value.units),
        })
    }

    async fn confirm_deposit(&self, _proof: DepositProof) -> Result<Credit, CoreError> {
        // A canned grant of service entitlement. Not money — byte-hours of relay service.
        Ok(Credit { units: 1024 })
    }

    async fn payout(&self, _redeemed: Credit, _dest: Payout) -> Result<TxRef, CoreError> {
        // The stub holds nothing and settles nothing: refuse rather than fabricate a TxRef.
        Err(CoreError::Unimplemented(
            "stub settlement backend cannot pay out",
        ))
    }

    async fn reserve_attestation(&self) -> Result<SolvencyProof, CoreError> {
        // Attests capacity to settle at the edge, not a held reserve (non-custodial).
        Ok(SolvencyProof {
            attestation: "stub-attestation:non-custodial".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quote_and_attest_are_canned_payout_refuses() {
        let s = StubSettlement;
        let quote = s.onramp_quote(Credit { units: 50 }).await.unwrap();
        assert!(quote.reference.contains("50"));

        let credit = s
            .confirm_deposit(DepositProof {
                reference: "anything".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(credit, Credit { units: 1024 });

        assert!(s.reserve_attestation().await.is_ok());

        let paid = s
            .payout(
                Credit { units: 1 },
                Payout {
                    destination: "anywhere".to_string(),
                },
            )
            .await;
        assert!(
            matches!(paid, Err(CoreError::Unimplemented(_))),
            "stub must not fabricate a settlement"
        );
    }

    /// §8.5 seam guard: nothing that crosses *above* the trait may name a chain, a coin, or a
    /// monetary amount. We serialize every value type the trait emits and assert the wire form
    /// is free of chain/currency identifiers. If a future backend or value-type change leaks one
    /// of these, this test fails — that is the early warning that the abstraction broke.
    #[tokio::test]
    async fn no_chain_identifier_leaks_above_the_trait() {
        let s = StubSettlement;
        let quote = s.onramp_quote(Credit { units: 7 }).await.unwrap();
        let credit = s
            .confirm_deposit(DepositProof {
                reference: "p".to_string(),
            })
            .await
            .unwrap();
        let attestation = s.reserve_attestation().await.unwrap();

        let surface = format!(
            "{} {} {} {}",
            serde_json::to_string(&quote).unwrap(),
            serde_json::to_string(&credit).unwrap(),
            serde_json::to_string(&attestation).unwrap(),
            // Include the abstract value types a consumer would also hand back.
            serde_json::to_string(&Payout {
                destination: "d".to_string()
            })
            .unwrap(),
        )
        .to_lowercase();

        const FORBIDDEN: &[&str] = &[
            "eth",
            "ethereum",
            "wei",
            "gwei",
            "erc20",
            "erc-20",
            "sol",
            "solana",
            "lamport",
            "spl",
            "btc",
            "bitcoin",
            "satoshi",
            "usdc",
            "usdt",
            "stablecoin",
            "wallet",
            "blockchain",
            "onchain",
            "on-chain",
            "fiat",
            "usd",
            "dollar",
            "0x",
        ];
        for needle in FORBIDDEN {
            assert!(
                !surface.contains(needle),
                "chain/currency identifier {needle:?} leaked above the settlement trait: {surface}"
            );
        }
    }
}
