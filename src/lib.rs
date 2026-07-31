//! Unofficial encrypted cloud-drive clients for Rust.
//!
//! Backend-specific APIs remain available through [`filen`] and [`internxt`].
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub use crisp_filen as filen;
pub use crisp_internxt as internxt;

/// Provider-neutral item information for callers that only need navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudItem {
    pub uuid: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// Provider-neutral conflict behavior for recursive transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    Fail,
    Skip,
    Overwrite,
}

/// Shared filename filtering shape. Provider clients may apply their own
/// wildcard semantics while preserving this wire-neutral representation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferFilter {
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
}

/// Shared progress event for UI, CLI, and logging consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferProgress {
    pub path: Option<std::path::PathBuf>,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub files_completed: u64,
    pub folders_completed: u64,
}

/// Cooperative cancellation token shared by blocking transfer operations.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Provider-neutral durable progress metadata. Provider-specific secrets and
/// encryption keys remain in the backend state types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeState {
    pub version: u8,
    pub provider: String,
    pub operation: String,
    pub remote_id: String,
    pub local_path: std::path::PathBuf,
    pub completed_units: Vec<u64>,
    pub total_units: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudErrorKind {
    Authentication,
    Authorization,
    NotFound,
    Conflict,
    Cancelled,
    Transport,
    Protocol,
    Integrity,
    LocalIo,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudError {
    pub kind: CloudErrorKind,
    pub message: String,
}

impl CloudError {
    pub fn new(kind: CloudErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// The intentionally small common capability surface. Provider-specific
/// authentication, crypto, transfer tuning, and mutation APIs remain on the
/// concrete clients.
pub trait CloudDrive {
    type Session;
    type Error;

    fn resolve_path(&self, session: &Self::Session, path: &Path) -> Result<CloudItem, Self::Error>;
    fn list_folder(
        &self,
        session: &Self::Session,
        folder: &CloudItem,
    ) -> Result<Vec<CloudItem>, Self::Error>;
}

impl CloudDrive for internxt::InternxtNativeClient {
    type Session = internxt::InternxtSession;
    type Error = anyhow::Error;

    fn resolve_path(&self, session: &Self::Session, path: &Path) -> Result<CloudItem, Self::Error> {
        Ok(self.resolve_path(session, path)?.into())
    }

    fn list_folder(
        &self,
        _session: &Self::Session,
        folder: &CloudItem,
    ) -> Result<Vec<CloudItem>, Self::Error> {
        self.list_folder(&folder.uuid)
            .map(|items| items.into_iter().map(Into::into).collect())
    }
}

impl From<internxt::NativeItem> for CloudItem {
    fn from(item: internxt::NativeItem) -> Self {
        Self {
            uuid: item.uuid,
            name: item.name,
            is_dir: item.is_dir,
            size: item.size,
        }
    }
}

impl CloudDrive for filen::FilenNativeClient {
    type Session = filen::FilenSession;
    type Error = anyhow::Error;

    fn resolve_path(&self, session: &Self::Session, path: &Path) -> Result<CloudItem, Self::Error> {
        Ok(self.resolve_path(session, path)?.into())
    }

    fn list_folder(
        &self,
        _session: &Self::Session,
        folder: &CloudItem,
    ) -> Result<Vec<CloudItem>, Self::Error> {
        self.list_folder(&folder.uuid)
            .map(|items| items.into_iter().map(Into::into).collect())
    }
}

impl From<filen::NativeItem> for CloudItem {
    fn from(item: filen::NativeItem) -> Self {
        Self {
            uuid: item.uuid,
            name: item.name,
            is_dir: item.is_dir,
            size: item.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_items_map_to_the_common_navigation_shape() {
        let item = CloudItem::from(internxt::NativeItem {
            name: "docs".into(),
            uuid: "folder-1".into(),
            is_dir: true,
            size: 0,
            modified_at: None,
        });
        assert_eq!(item.uuid, "folder-1");
        assert!(item.is_dir);
    }

    #[test]
    fn cancellation_token_is_cloneable_and_shared() {
        let first = CancellationToken::default();
        let second = first.clone();
        assert!(!second.is_cancelled());
        first.cancel();
        assert!(second.is_cancelled());
    }

    #[test]
    fn structured_cloud_error_preserves_classification() {
        let error = CloudError::new(CloudErrorKind::Integrity, "digest mismatch");
        assert_eq!(error.kind, CloudErrorKind::Integrity);
        assert_eq!(error.message, "digest mismatch");
    }
}
