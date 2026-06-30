//! S3 / MinIO-compatible [`BlobStore`] adapter (`s3` feature).
//!
//! Like [`crate::fs_blob`], the node holds only opaque, client-encrypted ciphertext
//! (`doc/design.md` §3.2); the content type is always `application/octet-stream` because the
//! node has no idea what the bytes are. Path-style addressing is forced for MinIO. Gated behind
//! the `s3` feature so filesystem-only deployments don't pull the AWS SDK.

use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;

use buh_core::CoreError;
use buh_core::ports::BlobStore;

/// Connection settings for an S3-compatible object store.
#[derive(Debug, Clone)]
pub struct S3Settings {
    /// Endpoint URL, e.g. `http://localhost:9000` for a local MinIO.
    pub endpoint: String,
    /// Region label. MinIO ignores it but the SDK requires one.
    pub region: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
}

/// An object store backed by an S3-compatible service.
pub struct S3BlobStore {
    client: Client,
}

impl S3BlobStore {
    /// Build a client from `settings`. Path-style addressing is forced because MinIO does not
    /// support virtual-host-style bucket addressing by default.
    #[must_use]
    pub fn new(settings: &S3Settings) -> Self {
        let creds = Credentials::new(
            &settings.access_key,
            &settings.secret_key,
            None,
            None,
            "buh-static",
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(&settings.endpoint)
            .region(Region::new(settings.region.clone()))
            .credentials_provider(creds)
            .force_path_style(true)
            .build();
        Self {
            client: Client::from_conf(config),
        }
    }

    /// Create `bucket` if it does not already exist (idempotent). Convenient for first deploys.
    pub async fn ensure_bucket(&self, bucket: &str) -> Result<(), CoreError> {
        match self.client.create_bucket().bucket(bucket).send().await {
            Ok(_) => Ok(()),
            Err(e) => {
                let svc = e.into_service_error();
                if svc.is_bucket_already_owned_by_you() || svc.is_bucket_already_exists() {
                    Ok(())
                } else {
                    Err(CoreError::Storage(svc.to_string()))
                }
            }
        }
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn exists(&self, bucket: &str, key: &str) -> Result<bool, CoreError> {
        match self
            .client
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let svc = e.into_service_error();
                if svc.is_not_found() {
                    Ok(false)
                } else {
                    Err(CoreError::Storage(svc.to_string()))
                }
            }
        }
    }

    async fn put(&self, bucket: &str, key: &str, bytes: Vec<u8>) -> Result<(), CoreError> {
        self.client
            .put_object()
            .bucket(bucket)
            .key(key)
            .content_type("application/octet-stream")
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| CoreError::Storage(e.into_service_error().to_string()))?;
        Ok(())
    }

    async fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, CoreError> {
        let out = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let svc = e.into_service_error();
                if svc.is_no_such_key() {
                    CoreError::NotFound
                } else {
                    CoreError::Storage(svc.to_string())
                }
            })?;
        let data = out
            .body
            .collect()
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(data.into_bytes().to_vec())
    }

    async fn presign_get(
        &self,
        bucket: &str,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<String, CoreError> {
        let presign = PresigningConfig::expires_in(Duration::from_secs(ttl_seconds))
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let req = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .presigned(presign)
            .await
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(req.uri().to_string())
    }
}
