use cosmwasm_std::{Api, CanonicalAddr, StdResult};
use serde::{Deserialize, Serialize};

use crate::contract_info::StoreContractInfo;
use crate::msg::Claim;
use crate::snip721::Metadata;

/// storage key for this contract's address
pub const MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// storage key for the admins list
pub const ADMINS_KEY: &[u8] = b"admin";
/// storage key for the claim info
pub const CLAIM_KEY: &[u8] = b"claim";
/// storage key for the rolling info
pub const ROLL_KEY: &[u8] = b"roll";
/// storage key for prng seed
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// prefix for storage of viewing keys
pub const PREFIX_VIEW_KEY: &[u8] = b"viewkeys";
/// prefix for storage of drawn NFTs over all rounds
pub const PREFIX_DRAWN: &[u8] = b"drawn";
/// prefix for storage mapping claimable NFTs to their iteration index
pub const PREFIX_WINNER_MAP: &[u8] = b"mapwin";
/// prefix for storage of drawn NFTs currently eligible for claims
pub const PREFIX_WINNER: &[u8] = b"winner";
/// prefix for storage of the counts of NFTs drawn in a round
pub const PREFIX_COUNTS: &[u8] = b"count";
/// prefix for storage of the redeemed NFTs
pub const PREFIX_REDEEM: &[u8] = b"rdem";
/// prefix for the storage of revoked permits
pub const PREFIX_REVOKED_PERMITS: &str = "revoke";

/// the info needed for claiming
#[derive(Serialize, Deserialize)]
pub struct ClaimInfo {
    /// code hash and address of the skulls contract
    pub skulls: StoreContractInfo,
    /// code hash and address of the partner contract
    pub partner: StoreContractInfo,
    /// code hash and address of the potion contract
    pub potion: StoreContractInfo,
    /// metadata for a potion
    pub meta: Metadata,
}

/// info needed when rolling
#[derive(Serialize, Deserialize)]
pub struct RollConfig {
    /// count of potions claimed
    pub claimed: u32,
    /// name of partner collection
    pub partner: String,
    /// number of tokens in the partner contract
    pub num_tokens: u32,
    /// true if the IDs are stringified ints starting with 1
    pub start_one: bool,
    /// round of rolling
    pub round: Option<u16>,
}

/// counts of unclaimed NFTs for one round
#[derive(Serialize, Deserialize)]
pub struct Counts {
    /// count of unclaimed skulls potions
    pub skulls: u32,
    /// count of unclaimed partner potions
    pub partner: u32,
}

/// data of a redeemed NFT
#[derive(Serialize, Deserialize)]
pub struct StoredRedeem {
    /// true if this was a skull claim
    pub is_skull: bool,
    /// token id of the redeemed NFT
    pub token_id: String,
    /// address of the claimer
    pub owner: CanonicalAddr,
    /// round this was claimed during
    pub round: u16,
}

impl StoredRedeem {
    /// Returns StdResult<Claim> from converting a StoredRedeem to a Claim
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    /// * `partner` - string slice of the partner collection name
    pub fn into_human<A: Api>(self, api: &A, partner: &str) -> StdResult<Claim> {
        let collection = if self.is_skull {
            "Mystic Skulls".to_string()
        } else {
            partner.to_string()
        };
        Ok(Claim {
            collection,
            token_id: self.token_id,
            owner: api.human_address(&self.owner)?,
            round: self.round,
        })
    }
}
