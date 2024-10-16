use cosmwasm_std::CanonicalAddr;
use serde::{Deserialize, Serialize};

/// storage key for the admins list
pub const ADMINS_KEY: &[u8] = b"admin";
/// storage key for the skull materials
pub const MATERIALS_KEY: &[u8] = b"mater";
/// storage key for the potion ingredients
pub const INGREDIENTS_KEY: &[u8] = b"ingr";
/// storage key for the staking sets of ingredients
pub const INGRED_SETS_KEY: &[u8] = b"seting";
/// storage key for the StakingState
pub const STAKING_STATE_KEY: &[u8] = b"stkst";
/// storage key for the AlchemyState
pub const ALCHEMY_STATE_KEY: &[u8] = b"alcst";
/// storage key for the skulls contract info
pub const SKULL_721_KEY: &[u8] = b"sk721";
/// storage key for crate contract infos
pub const CRATES_KEY: &[u8] = b"crat";
/// storage key for the svg server contract info
pub const SVG_SERVER_KEY: &[u8] = b"srvr";
/// storage prefix for the user's ingredient inventory
pub const PREFIX_USER_INGR_INVENTORY: &[u8] = b"usinv";
/// storage prefix for the staking set of a user
pub const PREFIX_USER_STAKE: &[u8] = b"usrsk";
/// storage prefix for a skull's staking info
pub const PREFIX_SKULL_STAKE: &[u8] = b"sklstk";
/// storage key for this contract's viewing key with other contracts
pub const MY_VIEWING_KEY: &[u8] = b"myview";
/// prefix for the storage of staking tables
pub const PREFIX_STAKING_TABLE: &[u8] = b"tbstk";
/// prefix for the storage of revoked permits
pub const PREFIX_REVOKED_PERMITS: &str = "revoke";

/// sets of ingredients
#[derive(Serialize, Deserialize)]
pub struct StoredIngrSet {
    /// name of the set
    pub name: String,
    /// list of ingredient indices in this set
    pub list: Vec<u8>,
}

/// ingredient sets and their staking weight
#[derive(Serialize, Deserialize)]
pub struct StoredSetWeight {
    /// idx of the set
    pub set: u8,
    /// weight
    pub weight: u16,
}

/// the latest staker, stake start, and claim time of a skull
#[derive(Serialize, Deserialize)]
pub struct SkullStakeInfo {
    pub addr: CanonicalAddr,
    pub stake: u64,
    pub claim: u64,
}
