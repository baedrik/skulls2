use crate::contract::BLOCK_SIZE;
use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use secret_toolkit::utils::HandleCallback;
use serde::{Deserialize, Serialize};

/// information about the minting of the NFT
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct MintRunInfo {
    /// optional address of the SNIP-721 contract creator
    pub collection_creator: Option<HumanAddr>,
    /// address of this minting contract as the NFT's creator
    pub token_creator: HumanAddr,
    /// optional time of minting (in seconds since 01/01/1970)
    pub time_of_minting: Option<u64>,
    /// number of the mint run this token was minted in.  This is
    /// used to serialize identical NFTs
    pub mint_run: u32,
    /// serial number in this mint run.  This is used to serialize
    /// identical NFTs
    pub serial_number: u32,
    /// optional total number of NFTs minted on this run.  This is used to
    /// represent that this token is number m of n
    pub quantity_minted_this_run: Option<u32>,
}

/// Serial number to give an NFT when minting
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct SerialNumber {
    /// number of the mint run this token will be minted in.  This is
    /// used to serialize identical NFTs
    pub mint_run: u32,
    /// serial number (in this mint run).  This is used to serialize
    /// identical NFTs
    pub serial_number: u32,
    /// optional total number of NFTs minted on this run.  This is used to
    /// represent that this token is number m of n
    pub quantity_minted_this_run: Option<u32>,
}

/// snip721 handle msgs
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Snip721HandleMsg {
    /// Mint multiple tokens
    BatchMintNft {
        /// list of mint operations to perform
        mints: Vec<Mint>,
    },
}

impl HandleCallback for Snip721HandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// token mint info used when doing a BatchMint
#[derive(Serialize)]
pub struct Mint {
    /// owner addres
    pub owner: HumanAddr,
    /// optional public metadata that can be seen by everyone
    pub public_metadata: Metadata,
    /// optional memo for the tx
    pub memo: String,
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}

/// token metadata stripped down only to what is used by the claim contract
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct Metadata {
    /// optional on-chain metadata
    pub extension: Extension,
}

/// metadata extension
/// You can add any metadata fields you need here.  These fields are based on
/// https://docs.opensea.io/docs/metadata-standards and are the metadata fields that
/// Stashh uses for robust NFT display.  Urls should be prefixed with `http://`, `https://`, `ipfs://`, or
/// `ar://`
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct Extension {
    /// url to the image
    pub image: String,
    /// item description
    pub description: String,
    /// name of the item
    pub name: String,
    /// item attributes
    pub attributes: Vec<Trait>,
}

/// attribute trait
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct Trait {
    /// name of the trait
    pub trait_type: String,
    /// trait value
    pub value: String,
}
