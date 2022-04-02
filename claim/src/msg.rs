use crate::contract_info::ContractInfo;
use crate::snip721::Metadata;
use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// admins in addition to the instantiator
    pub admins: Option<Vec<HumanAddr>>,
    /// code hash and address of the skulls contract
    pub skulls_contract: ContractInfo,
    /// info about the partner collection
    pub partner_info: PartnerInfo,
    /// code hash and address of the potion contract
    pub potion_contract: ContractInfo,
    /// metadata for the minted potions
    pub metadata: Metadata,
    /// entropy used for prng seed
    pub entropy: String,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// select random NFTs that can be used to claim potions
    Raffle {
        /// number of winners to draw
        num_picks: u32,
        /// percentage of winners that should go to partner NFT owners
        partner_percent: u8,
        /// entropy for the prng
        entropy: String,
    },
    /// BatchReceiveNft is called by the NFT contract to claim potions using the sent NFTs
    BatchReceiveNft {
        /// address of the owner of the tokens being used to claim
        from: HumanAddr,
        /// list of tokens sent (used to claim)
        token_ids: Vec<String>,
    },
    /// ReceiveNft is only included to maintatin CW721 compliance.  Hopefully everyone uses the
    /// superior BatchReceiveNft process.  ReceiveNft is called by the NFT contract to claim a potion
    /// using the sent NFT
    ReceiveNft {
        /// address of the owner of the token being used to claim
        sender: HumanAddr,
        /// the token sent (used to claim)
        token_id: String,
    },
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
        admins: Vec<HumanAddr>,
    },
    /// allows an admin to remove admin addresses
    RemoveAdmins {
        /// list of address to revoke admin priveleges from
        admins: Vec<HumanAddr>,
    },
    /// disallow the use of a permit
    RevokePermit {
        /// name of the permit that is no longer valid
        permit_name: String,
    },
    /// set a viewing key with an nft contract to facilitate in retrieval of an NFT from an unregistered collection
    SetViewingKeyWithCollection {
        /// the code hash and address of the nft contract
        nft_contract: ContractInfo,
        /// viewing key to set with the nft contract
        viewing_key: String,
    },
    /// retrieve an nft that was sent from an unregistered collection
    RetrieveNft {
        /// the code hash and address of the nft contract
        nft_contract: ContractInfo,
        /// ids of the tokens to transfer to the admin doing this tx
        token_ids: Vec<String>,
    },
}

/// Responses from handle functions
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    /// response of both AddAdmins and RemoveAdmins
    AdminsList {
        /// current admins
        admins: Vec<HumanAddr>,
    },
    /// response from creating a viewing key
    ViewingKey {
        key: String,
    },
    RevokePermit {
        status: String,
    },
    RetrieveNft {
        status: String,
    },
    /// response from selecting NFTs
    Raffle {
        /// number of skulls selected
        skulls: u32,
        /// number of partner NFTs selected
        partner: u32,
    },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the skulls eligible to claim
    SkullsRedeemable {
        /// optional selection round.  Defaults to the current round since
        /// those are the only ones still eligible
        round: Option<u16>,
        /// optional page
        page: Option<u32>,
        /// optional max number of token IDs to display (defaults to 100)
        page_size: Option<u32>,
    },
    /// display the partner NFTs eligible to claim
    PartnerRedeemable {
        /// optional selection round.  Defaults to the current round since
        /// those are the only ones still eligible
        round: Option<u16>,
        /// optional page
        page: Option<u32>,
        /// optional max number of token IDs to display (defaults to 100)
        page_size: Option<u32>,
    },
    /// display the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the NFTs that have been redeemed
    Claimed {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page
        page: Option<u32>,
        /// optional max number of token IDs to display (defaults to 30)
        page_size: Option<u32>,
    },
    /// check if any of the supplied NFTs are eligible to claim potions
    WhichAreWinners {
        /// list of skulls to check
        skulls: Vec<String>,
        /// list of partner NFTs to check
        partner: Vec<String>,
    },
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// displays the NFTs eligible to claim potions
    Redeemable {
        /// raffle round
        round: u16,
        /// collection name
        collection: String,
        /// count of redeemable NFTs for this collection/round
        count: u32,
        /// token IDs
        token_ids: Vec<String>,
    },
    /// displays the admins list
    Admins {
        /// current admin list
        admins: Vec<HumanAddr>,
    },
    /// list of which of the supplied token IDs are able to claim potions
    WhichAreWinners {
        /// winning skulls
        skulls: Vec<String>,
        /// winning partner NFTs
        partner: Vec<String>,
    },
    /// list of claims
    Claimed {
        /// number of potions claimed
        count: u32,
        /// list of claims
        claims: Vec<Claim>,
    },
}

/// claim info
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct Claim {
    /// collection name
    pub collection: String,
    /// token ID
    pub token_id: String,
    /// address that claimed
    pub owner: HumanAddr,
    /// round the NFT was redeemed
    pub round: u16,
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}

/// info about the partner collection
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct PartnerInfo {
    /// name of the collection
    pub name: String,
    /// code hash and address of the collection contract
    pub contract: ContractInfo,
    /// number of tokens in the partner collection
    pub count: u32,
    /// optionally true if the stringified int token ids start at 1 instead of 0.
    /// Defaults to false
    pub starts_at_one: Option<bool>,
}
