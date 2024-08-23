use crate::metadata::Metadata;
use crate::state::{
    Category, PREFIX_CATEGORY, PREFIX_CATEGORY_MAP, PREFIX_VARIANT, PREFIX_VARIANT_MAP,
};
use crate::storage::may_load;
use cosmwasm_std::{Addr, StdError, StdResult, Storage};
use cosmwasm_storage::ReadonlyPrefixedStorage;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    /// optional addresses to add as admins in addition to the instantiator
    pub admins: Option<Vec<String>>,
    /// entropy used for prng seed
    pub entropy: String,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Create a viewing key
    CreateViewingKey { entropy: String },
    /// Set a viewing key
    SetViewingKey {
        key: String,
        // optional padding can be used so message length doesn't betray key length
        padding: Option<String>,
    },
    /// allows an admin to add more admins
    AddAdmins {
        /// list of address to grant admin priveleges
        admins: Vec<String>,
    },
    /// allows an admin to remove admin addresses
    RemoveAdmins {
        /// list of address to revoke admin priveleges from
        admins: Vec<String>,
    },
    /// allows an admin to add more viewers
    AddViewers {
        /// list of new addresses with viewing priveleges
        viewers: Vec<String>,
    },
    /// allows an admin to remove viewer addresses
    RemoveViewers {
        /// list of address to revoke viewing priveleges from
        viewers: Vec<String>,
    },
    /// allows an admin to add minters
    AddMinters {
        /// list of new addresses with viewing priveleges
        minters: Vec<String>,
    },
    /// allows an admin to remove minter addresses
    RemoveMinters {
        /// list of address to revoke viewing priveleges from
        minters: Vec<String>,
    },
    /// add new trait categories
    AddCategories { categories: Vec<CategoryInfo> },
    /// add new trait variants to existing categories
    AddVariants { variants: Vec<AddVariantInfo> },
    /// change the name or skip status for an existing trait category
    ModifyCategory {
        /// name of the trait category to modify
        name: String,
        /// optional new name for the trait category
        new_name: Option<String>,
        /// optional new skip status (true if this category is never rolled)
        new_skip: Option<bool>,
    },
    /// modify existing trait variants
    ModifyVariants { modifications: Vec<VariantModInfo> },
    /// set the common metadata for the collection
    SetMetadata {
        /// common public metadata
        public_metadata: Option<Metadata>,
        /// common private metadata
        private_metadata: Option<Metadata>,
    },
    /// add dependencies for traits that have multiple layers
    AddDependencies {
        /// new dependencies to add
        dependencies: Vec<Dependencies>,
    },
    /// remove dependecies from trait variants
    RemoveDependencies {
        /// dependencies to remove
        dependencies: Vec<Dependencies>,
    },
    /// modify dependencies of a trait variant
    ModifyDependencies {
        /// dependencies to modify
        dependencies: Vec<Dependencies>,
    },
    /// disallow the use of a permit
    RevokePermit {
        /// name of the permit that is no longer valid
        permit_name: String,
    },
}

/// Responses from handle functions
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteAnswer {
    /// response from creating a viewing key
    ViewingKey { key: String },
    /// response from adding/removing admins
    AdminsList {
        // current admins
        admins: Vec<Addr>,
    },
    /// response from adding/removing viewers
    ViewersList {
        // current viewers
        viewers: Vec<Addr>,
    },
    /// response from adding/removing minters
    MintersList {
        // current operators
        minters: Vec<Addr>,
    },
    /// response from adding new trait categories
    AddCategories {
        /// number of categories
        count: u8,
    },
    /// response from adding new trait variants
    AddVariants { status: String },
    /// response from modifying a trait category
    ModifyCategory { status: String },
    /// response from modifying existing trait variants
    ModifyVariants { status: String },
    /// response from setting common metadata
    SetMetadata { metadata: CommonMetadata },
    /// response from adding dependencies
    AddDependencies { status: String },
    /// response from removing dependencies
    RemoveDependencies { status: String },
    /// response from modifying dependencies
    ModifyDependencies { status: String },
    /// response from revoking a permit
    RevokePermit { status: String },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// displays the category count and which ones are skipped when rolling
    State {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// lists the authorized addresses for this server
    AuthorizedAddresses {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays a trait category
    Category {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional category name to display
        name: Option<String>,
        /// optional category index to display
        index: Option<u8>,
        /// optional trait variant index to start at
        start_at: Option<u8>,
        /// max number of variants to display
        limit: Option<u8>,
        /// optionally true if svgs should be displayed.  Defaults to false
        display_svg: Option<bool>,
    },
    /// displays a layer variant
    Variant {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optionally display by the category and variant names
        by_name: Option<LayerId>,
        /// optionally display by the category and variant indices
        by_index: Option<StoredLayerId>,
        /// optionally true if svgs should be displayed.  Defaults to false
        display_svg: Option<bool>,
    },
    /// displays the common metadata
    CommonMetadata {
        /// optional address and viewing key of an admin, minter, or viewer
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the trait variants with dependencies (multiple layers)
    Dependencies {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional dependency index to start at
        start_at: Option<u16>,
        /// max number of dependencies to display
        limit: Option<u16>,
    },
    /// generates metadata from the input image vector
    TokenMetadata {
        /// optional address and viewing key of an admin, minter or viewer
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// image indices
        image: Vec<u8>,
    },
    /// display info that achemy/reveal contracts will need
    ServeAlchemy {
        /// address and viewing key of a reveal contract
        viewer: ViewerInfo,
    },
    /// display if a skull is a cyclops and if it is jawless
    SkullType {
        /// address and viewing key of the alchemy contract
        viewer: ViewerInfo,
        /// image indices
        image: Vec<u8>,
    },
    /// return the new image vec resulting from altering the specified layers
    Transmute {
        /// address and viewing key of the alchemy contract
        viewer: ViewerInfo,
        /// current image indices
        current: Vec<u8>,
        /// transmuted layers
        new_layers: Vec<LayerId>,
    },
    /// display the StoredLayerId for jawless and cyclops
    SkullTypeLayerIds {
        /// address and viewing key of the alchemy contract
        viewer: ViewerInfo,
    },
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// response listing the current authorized addresses
    AuthorizedAddresses {
        admins: Vec<Addr>,
        minters: Vec<Addr>,
        viewers: Vec<Addr>,
    },
    /// display a trait category
    Category {
        /// number of categories
        category_count: u8,
        /// this category's index
        index: u8,
        /// trait category name
        name: String,
        /// true if this category is skipped during rolls
        skip: bool,
        /// number of variants in this category
        variant_count: u8,
        /// paginated variants for this category
        variants: Vec<VariantInfoPlus>,
    },
    /// display a layer variant
    Variant {
        /// the index of the category this variant belongs to
        category_index: u8,
        /// all the variant info
        info: VariantInfoPlus,
    },
    /// response for both CommonMetadata and TokenMetadata
    Metadata {
        public_metadata: Option<Metadata>,
        private_metadata: Option<Metadata>,
    },
    /// displays the trait variants with dependencies (multiple layers)
    Dependencies {
        /// number of dependencies
        count: u16,
        dependencies: Vec<Dependencies>,
    },
    /// info needed by alchemy/reveal contracts
    ServeAlchemy {
        /// categories that are skipped when rolling/revealing
        skip: Vec<u8>,
        /// variant display dependencies
        dependencies: Vec<StoredDependencies>,
        /// category names
        category_names: Vec<String>,
    },
    /// state info
    State {
        /// number of categories
        category_count: u8,
        /// categories that are skipped when rolling
        skip: Vec<String>,
    },
    /// display if a skull is a cyclops and if it is jawless
    SkullType {
        /// true if the skull is a cyclops
        is_cyclops: bool,
        /// true if the skull is jawless
        is_jawless: bool,
    },
    /// display the new image vec after transmuting the requested layers
    Transmute {
        /// new image
        image: Vec<u8>,
    },
    /// display the StoredLayerId for jawless and cyclops
    SkullTypeLayerIds {
        /// cyclops layer
        cyclops: StoredLayerId,
        /// jawless layer
        jawless: StoredLayerId,
    },
}

/// trait variant information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct VariantInfo {
    /// trait variant name
    pub name: String,
    /// display name of the trait variant
    pub display_name: String,
    /// svg data if name is not `None`
    pub svg: Option<String>,
}

/// trait variant information with its index and dependencies
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct VariantInfoPlus {
    /// index of variant
    pub index: u8,
    /// variant info
    pub variant_info: VariantInfo,
    /// layer variants it includes
    pub includes: Vec<LayerId>,
}

/// trait category information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct CategoryInfo {
    /// trait category name
    pub name: String,
    /// true if this category is skipped when rolling
    pub skip: bool,
    /// variants for this category
    pub variants: Vec<VariantInfo>,
}

/// information for adding variants
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct AddVariantInfo {
    /// trait category name
    pub category_name: String,
    /// new variants for this category
    pub variants: Vec<VariantInfo>,
}

/// info needed to call ModifyVariants
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct VariantModInfo {
    /// trait category name
    pub category: String,
    /// modifications to make to variants in this category
    pub modifications: Vec<VariantModification>,
}

/// info needed to modify trait variants
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct VariantModification {
    /// (old) trait variant name
    pub name: String,
    /// new variant data (may include a variant name change)
    pub modified_variant: VariantInfo,
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: String,
    /// authentication key string
    pub viewing_key: String,
}

/// describes a trait that has multiple layers
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct Dependencies {
    /// id of the layer variant that has dependencies
    pub id: LayerId,
    /// the other layers that are correlated to this variant
    pub correlated: Vec<LayerId>,
}

impl Dependencies {
    /// Returns StdResult<StoredDependencies> from creating a StoredDependencies from a Dependencies
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    pub fn to_stored(&self, storage: &dyn Storage) -> StdResult<StoredDependencies> {
        Ok(StoredDependencies {
            id: self.id.to_stored(storage)?,
            correlated: self
                .correlated
                .iter()
                .map(|l| l.to_stored(storage))
                .collect::<StdResult<Vec<StoredLayerId>>>()?,
        })
    }
}

/// identifies a layer
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct LayerId {
    /// the layer category name
    pub category: String,
    /// the variant name
    pub variant: String,
}

impl LayerId {
    /// Returns StdResult<StoredLayerId> from creating a StoredLayerId from a LayerId
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    pub fn to_stored(&self, storage: &dyn Storage) -> StdResult<StoredLayerId> {
        let cat_map = ReadonlyPrefixedStorage::new(storage, PREFIX_CATEGORY_MAP);
        let cat_idx: u8 = may_load(&cat_map, self.category.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!("Category name:  {} does not exist", &self.category))
        })?;
        let var_map = ReadonlyPrefixedStorage::multilevel(
            storage,
            &[PREFIX_VARIANT_MAP, &cat_idx.to_le_bytes()],
        );
        let var_idx: u8 = may_load(&var_map, self.variant.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!(
                "Category {} does not have a variant named {}",
                &self.category, &self.variant
            ))
        })?;

        Ok(StoredLayerId {
            category: cat_idx,
            variant: var_idx,
        })
    }
}

/// identifies a layer
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct StoredLayerId {
    /// the layer category
    pub category: u8,
    pub variant: u8,
}

impl StoredLayerId {
    /// Returns StdResult<LayerId> from creating a LayerId from a StoredLayerId
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    pub fn to_display(&self, storage: &dyn Storage) -> StdResult<LayerId> {
        let cat_store = ReadonlyPrefixedStorage::new(storage, PREFIX_CATEGORY);
        let cat_key = self.category.to_le_bytes();
        let cat: Category = may_load(&cat_store, &cat_key)?
            .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
        let var_store = ReadonlyPrefixedStorage::multilevel(storage, &[PREFIX_VARIANT, &cat_key]);
        let var: VariantInfo = may_load(&var_store, &self.variant.to_le_bytes())?
            .ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
        Ok(LayerId {
            category: cat.name,
            variant: var.name,
        })
    }
}

/// the metadata common to all NFTs
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct CommonMetadata {
    /// common public metadata
    pub public: Option<Metadata>,
    /// common privae metadata
    pub private: Option<Metadata>,
}

/// describes a trait that has multiple layers
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct StoredDependencies {
    /// id of the layer variant that has dependencies
    pub id: StoredLayerId,
    /// the other layers that are correlated to this variant
    pub correlated: Vec<StoredLayerId>,
}

impl StoredDependencies {
    /// Returns StdResult<Dependencies> from creating a Dependencies from a StoredDependencies
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract storage
    pub fn to_display(&self, storage: &dyn Storage) -> StdResult<Dependencies> {
        Ok(Dependencies {
            id: self.id.to_display(storage)?,
            correlated: self
                .correlated
                .iter()
                .map(|l| l.to_display(storage))
                .collect::<StdResult<Vec<LayerId>>>()?,
        })
    }
}
