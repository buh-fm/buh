//! Filesystem-backed [`BlobStore`] for local / ZFS deployments.
//!
//! Stores each object as a file at `root/bucket/key`. The node holds opaque ciphertext: media
//! is sealed client-side under a per-file content key before it ever arrives here
//! (`doc/design.md` §3.2), so these bytes are unreadable to the node.
//!
//! Bucket and key arrive from the HTTP path and are attacker-controlled, so [`resolve`] rejects
//! any component that could escape `root` (`..`, absolute paths, empty or `.` segments,
//! backslashes). Keys may contain `/` to nest, but every segment is validated.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs;

use buh_core::CoreError;
use buh_core::ports::BlobStore;

/// An object store backed by a directory tree on the local filesystem.
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// Create a store rooted at `root` (created on first write; need not exist yet).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve `bucket`/`key` to a path under `root`, rejecting anything that could escape it.
    fn resolve(&self, bucket: &str, key: &str) -> Result<PathBuf, CoreError> {
        let mut path = self.root.join(safe_segment(bucket)?);
        if key.is_empty() {
            return Err(CoreError::Validation(buh_entities::EntityError::Empty(
                "blob key",
            )));
        }
        for segment in key.split('/') {
            path.push(safe_segment(segment)?);
        }
        Ok(path)
    }
}

/// Validate a single path component: non-empty, not `.`/`..`, no separators or NUL.
fn safe_segment(segment: &str) -> Result<&str, CoreError> {
    let bad = segment.is_empty()
        || segment == "."
        || segment == ".."
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('\0');
    if bad {
        return Err(CoreError::Validation(
            buh_entities::EntityError::InvalidPayload("unsafe blob path component"),
        ));
    }
    Ok(segment)
}

fn storage<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Storage(e.to_string())
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn exists(&self, bucket: &str, key: &str) -> Result<bool, CoreError> {
        let path = self.resolve(bucket, key)?;
        match fs::metadata(&path).await {
            Ok(meta) => Ok(meta.is_file()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(storage(e)),
        }
    }

    async fn put(&self, bucket: &str, key: &str, bytes: Vec<u8>) -> Result<(), CoreError> {
        let path = self.resolve(bucket, key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(storage)?;
        }
        // Write to a sibling temp file then rename, so a concurrent reader never sees a
        // half-written object. The temp name includes the object name to avoid collisions.
        let tmp = tmp_path(&path);
        fs::write(&tmp, &bytes).await.map_err(storage)?;
        fs::rename(&tmp, &path).await.map_err(storage)?;
        Ok(())
    }

    async fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, CoreError> {
        let path = self.resolve(bucket, key)?;
        match fs::read(&path).await {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(CoreError::NotFound),
            Err(e) => Err(storage(e)),
        }
    }

    async fn presign_get(
        &self,
        _bucket: &str,
        _key: &str,
        _ttl_seconds: u64,
    ) -> Result<String, CoreError> {
        // No object-store edge to redirect to: filesystem blobs are served by the node's own
        // GET handler. Callers fall back to a direct fetch when presigning is unavailable.
        Err(CoreError::Unimplemented(
            "filesystem blob store does not support presigned URLs",
        ))
    }
}

/// A temp path adjacent to `path` for atomic-rename writes.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (FsBlobStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (FsBlobStore::new(dir.path()), dir)
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let (s, _dir) = store().await;
        let bytes = b"opaque ciphertext".to_vec();
        assert!(!s.exists("media", "a/b/c").await.unwrap());
        s.put("media", "a/b/c", bytes.clone()).await.unwrap();
        assert!(s.exists("media", "a/b/c").await.unwrap());
        assert_eq!(s.get("media", "a/b/c").await.unwrap(), bytes);
    }

    #[tokio::test]
    async fn missing_get_is_not_found() {
        let (s, _dir) = store().await;
        assert!(matches!(
            s.get("media", "nope").await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn overwrite_replaces() {
        let (s, _dir) = store().await;
        s.put("b", "k", b"one".to_vec()).await.unwrap();
        s.put("b", "k", b"two".to_vec()).await.unwrap();
        assert_eq!(s.get("b", "k").await.unwrap(), b"two");
    }

    #[tokio::test]
    async fn path_traversal_is_rejected() {
        let (s, _dir) = store().await;
        for (bucket, key) in [
            ("..", "k"),
            ("b", "../escape"),
            ("b", "a/../../escape"),
            ("b", "/abs"),
            ("b", ""),
            (".", "k"),
        ] {
            assert!(
                s.get(bucket, key).await.is_err(),
                "expected {bucket}/{key} rejected"
            );
            assert!(s.put(bucket, key, b"x".to_vec()).await.is_err());
        }
    }

    #[tokio::test]
    async fn presign_is_unsupported() {
        let (s, _dir) = store().await;
        assert!(matches!(
            s.presign_get("b", "k", 60).await,
            Err(CoreError::Unimplemented(_))
        ));
    }
}
