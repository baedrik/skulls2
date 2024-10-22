use crate::contract::BLOCK_SIZE;
use crate::contract_info::ContractInfo;
use crate::msg::ViewerInfo;
use schemars::JsonSchema;
use secret_toolkit::utils::{HandleCallback, Query};
use serde::{Deserialize, Serialize};

/// snip721 handle msgs
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Snip721HandleMsg {
    /// set a token's ImageInfo.  This can only be called be an authorized minter
    SetImageInfo {
        /// id of the token whose image info should be updated
        token_id: String,
        /// the new image info
        image_info: ImageInfo,
    },
    /// set viewing key
    SetViewingKey {
        /// desired viewing key
        key: String,
    },
    /// mint new token
    MintNft {
        /// owner address
        owner: String,
        /// public metadata that can be seen by everyone
        public_metadata: Metadata,
    },
    /// register this contract's code hash with the snip721
    RegisterReceiveNft {
        /// this contract's code hash
        code_hash: String,
        /// true because this contract also implements BatchReceiveNft
        also_implements_batch_receive_nft: bool,
    },
    /// burn many tokens
    BatchBurnNft {
        /// list of burns to perform
        burns: Vec<Burn>,
    },
}

impl HandleCallback for Snip721HandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// token burn info used when doing a BatchBurnNft
#[derive(Serialize)]
pub struct Burn {
    /// tokens being burnt
    pub token_ids: Vec<String>,
}

/// snip721 query msgs
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Snip721QueryMsg {
    /// displays the public metadata of a token
    NftInfo { token_id: String },
    /// display a token's ImageInfo
    ImageInfo {
        /// token whose image info to display
        token_id: String,
        /// address and viewing key of the querier
        viewer: ViewerInfo,
    },
    /// displays public info of multiple tokens
    BatchNftDossier { token_ids: Vec<String> },
}

impl Query for Snip721QueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// wrapper used to deserialize the snip721 NftInfo query
#[derive(Deserialize)]
pub struct NftInfoWrapper {
    pub nft_info: Metadata,
}

/// snip721 BatchNftDossier query item
#[derive(Deserialize)]
pub struct BatchNftDossierElement {
    //    pub token_id: String,
    pub public_metadata: Metadata,
}

/// snip721 BatchNftDossier query response
#[derive(Deserialize)]
pub struct BatchNftDossierResponse {
    pub nft_dossiers: Vec<BatchNftDossierElement>,
}

/// wrapper used to deserialize the snip721 BatchNftDossier query
#[derive(Deserialize)]
pub struct BatchNftDossierWrapper {
    pub batch_nft_dossier: BatchNftDossierResponse,
}

/// data that determines a token's appearance
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug, Default)]
pub struct ImageInfo {
    /// current image svg index array
    pub current: Vec<u8>,
    /// previous image svg index array
    pub previous: Vec<u8>,
    /// complete initial genetic image svg index array
    pub natural: Vec<u8>,
    /// optional svg server contract if not using the default
    pub svg_server: Option<String>,
}

/// snip721 ImageInfo response
#[derive(Deserialize)]
pub struct ImageInfoResponse {
    /// owner of the token
    pub owner: String,
    /// address and code hash of the svg server this token is using,
    pub server_used: ContractInfo,
    /// token's image info
    pub image_info: ImageInfo,
}

/// wrapper used to deserialize the snip721 ImageInfo query
#[derive(Deserialize)]
pub struct ImageInfoWrapper {
    pub image_info: ImageInfoResponse,
}

/// structure for Send msgs
#[derive(Deserialize)]
pub struct SendMsg {
    /// the token id of the skull to apply the potion to
    pub skull: String,
}

/// token metadata
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug, Default)]
pub struct Metadata {
    /// on-chain metadata
    pub extension: Extension,
}

/// metadata extension
/// You can add any metadata fields you need here.  These fields are based on
/// https://docs.opensea.io/docs/metadata-standards and are the metadata fields that
/// Stashh uses for robust NFT display.  Urls should be prefixed with `http://`, `https://`, `ipfs://`, or
/// `ar://`
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug, Default)]
pub struct Extension {
    /// url to the image
    pub image: Option<String>,
    /// raw SVG image data (not recommended). Only use this if you're not including the image parameter
    pub image_data: Option<String>,
    /// item description
    pub description: Option<String>,
    /// name of the item
    pub name: Option<String>,
    /// item attributes
    pub attributes: Option<Vec<Trait>>,
}

/// attribute trait
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug, Default)]
pub struct Trait {
    /// name of the trait
    pub trait_type: String,
    /// trait value
    pub value: String,
}
