use crate::contract::BLOCK_SIZE;
use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use secret_toolkit::utils::HandleCallback;
use serde::{Deserialize, Serialize};

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
