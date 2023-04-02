use serde::{Deserialize, Serialize};

/// storage key for the admins list
pub const ADMINS_KEY: &[u8] = b"admin";
/// storage key for the viewers list
pub const VIEWERS_KEY: &[u8] = b"vwers";
/// storage key for the minters list
pub const MINTERS_KEY: &[u8] = b"mntrs";
/// storage key for this server's address
pub const MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// storage key for prng seed
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// storage key for the State
pub const STATE_KEY: &[u8] = b"state";
/// storage key for the variant dependencies
pub const DEPENDENCIES_KEY: &[u8] = b"depend";
/// storage key for the common metadata
pub const METADATA_KEY: &[u8] = b"metadata";
/// storage prefix for mapping a category name to its index
pub const PREFIX_CATEGORY_MAP: &[u8] = b"catemap";
/// storage prefix for mapping a variant name to its index
pub const PREFIX_VARIANT_MAP: &[u8] = b"vrntmap";
/// prefix for the storage of categories
pub const PREFIX_CATEGORY: &[u8] = b"category";
/// prefix for the storage of category variants
pub const PREFIX_VARIANT: &[u8] = b"variant";
/// prefix for storage of viewing keys
pub const PREFIX_VIEW_KEY: &[u8] = b"viewkey";
/// prefix for the storage of revoked permits
pub const PREFIX_REVOKED_PERMITS: &str = "revoke";

/// trait category
#[derive(Serialize, Deserialize)]
pub struct Category {
    /// name
    pub name: String,
    /// true if this category is skipped during rolls
    pub skip: bool,
    /// count of variants in this category
    pub cnt: u8,
}

/// config values needed when rolling a new NFT
#[derive(Serialize, Deserialize)]
pub struct State {
    /// number of categories
    pub cat_cnt: u8,
    /// layer indices to skip when rolling
    pub skip: Vec<u8>,
}
