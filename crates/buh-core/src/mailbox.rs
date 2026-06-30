//! Relay/mailbox orchestration.
//!
//! Deliberately thin: a blind relay has almost no business logic. What lives here is input
//! clamping (TTL, payload size, pull limit) and delegation to the [`MailboxRepo`] port. We
//! keep it as a seam (rather than calling the repo straight from handlers) so policy is
//! testable against an in-memory fake and stays out of the HTTP layer.

use chrono::Utc;

use buh_entities::{EntityError, EnvelopeId, NewEnvelope, PushEnvelope, QueueId, StoredEnvelope};

use crate::context::Ctx;
use crate::error::CoreError;

/// Validate and push a sealed envelope to a queue. The TTL is clamped to node policy; an
/// out-of-range request is clamped rather than rejected. The payload must be non-empty and
/// within the size limit.
pub async fn push(
    ctx: &Ctx,
    queue_id: &QueueId,
    req: PushEnvelope,
) -> Result<EnvelopeId, CoreError> {
    if req.payload.is_empty() {
        return Err(EntityError::InvalidPayload("empty").into());
    }
    if req.payload.len() > ctx.config.max_payload_bytes {
        return Err(EntityError::InvalidPayload("exceeds size limit").into());
    }

    let ttl = clamp_ttl(req.ttl_seconds, &ctx.config);
    let envelope = NewEnvelope {
        payload: req.payload,
        ttl_seconds: ttl,
    };
    ctx.mailbox.push(queue_id, &envelope).await
}

/// Pull up to `limit` live envelopes for a queue (clamped to `[1, max_pull_limit]`).
pub async fn pull(
    ctx: &Ctx,
    queue_id: &QueueId,
    limit: i64,
) -> Result<Vec<StoredEnvelope>, CoreError> {
    let limit = limit.clamp(1, ctx.config.max_pull_limit);
    ctx.mailbox.pull(queue_id, limit).await
}

/// Acknowledge delivery of an envelope. Returns `false` if it was not present.
pub async fn ack(
    ctx: &Ctx,
    queue_id: &QueueId,
    envelope_id: EnvelopeId,
) -> Result<bool, CoreError> {
    ctx.mailbox.ack(queue_id, envelope_id, Utc::now()).await
}

/// Sweep expired envelopes across all queues. Returns the number removed.
pub async fn sweep(ctx: &Ctx) -> Result<u64, CoreError> {
    ctx.mailbox.expire(Utc::now()).await
}

/// Clamp a requested TTL to `[1, max]`, substituting the default when non-positive.
fn clamp_ttl(requested: i64, config: &crate::context::CoreConfig) -> i64 {
    if requested <= 0 {
        config.default_ttl_seconds
    } else {
        requested.min(config.max_ttl_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::CoreConfig;

    #[test]
    fn ttl_clamping() {
        let c = CoreConfig::default();
        assert_eq!(clamp_ttl(0, &c), c.default_ttl_seconds);
        assert_eq!(clamp_ttl(-5, &c), c.default_ttl_seconds);
        assert_eq!(clamp_ttl(60, &c), 60);
        assert_eq!(clamp_ttl(i64::MAX, &c), c.max_ttl_seconds);
    }
}
