use serde::{Deserialize, Serialize};

use crate::contract_info::StoreContractInfo;
use crate::msg::VariantInfo;

/// storage key for this contract's address
pub const MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// storage key for the admins list
pub const ADMINS_KEY: &[u8] = b"admin";
/// storage key for the claim info
pub const STATE_KEY: &[u8] = b"state";
/// storage key for prng seed
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// prefix for storage of viewing keys
pub const PREFIX_VIEW_KEY: &[u8] = b"viewkeys";
/// prefix for the storage of revoked permits
pub const PREFIX_REVOKED_PERMITS: &str = "revoke";
/// prefix for storage that maps potion names to their indices
pub const PREFIX_POTION_IDX: &[u8] = b"potidx";
/// prefix for storage of potion infos
pub const PREFIX_POTION: &[u8] = b"potn";

/// the contract state
#[derive(Serialize, Deserialize)]
pub struct State {
    /// code hash and address of the skulls contract
    pub skulls: StoreContractInfo,
    /// list of potion contracts that might call
    pub potion_contracts: Vec<StoreContractInfo>,
    /// list of svg servers
    pub svg_contracts: Vec<StoreContractInfo>,
    /// number of potions
    pub potion_cnt: u16,
    /// viewing key used with svg servers
    pub v_key: String,
    /// true if alchemy should be halted
    pub halt: bool,
}

/// stored potion information
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoredPotionInfo {
    /// potion name
    pub name: String,
    /// index of the svg server the potion uses
    pub svg_server: u8,
    /// possible traits and their weights
    pub variants: Vec<VariantInfo>,
    /// true if use of this potion is halted
    pub halt: bool,
}
