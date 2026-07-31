//! Unofficial encrypted cloud-drive clients for Rust.
//!
//! Backend-specific APIs remain available through [`filen`] and [`internxt`].
use std::path::Path;

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
}
