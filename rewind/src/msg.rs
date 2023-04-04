#![allow(clippy::large_enum_variant)]
use crate::contract_info::ContractInfo;
use crate::snip721::ViewerInfo;
use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// code hash and address of the nft contract
    pub nft_contract: ContractInfo,
    /// code hash and address of an svg server contract
    pub svg_server: ContractInfo,
    /// entropy used for prng seed
    pub entropy: String,
    /// cooldown period for rewinds
    pub cooldown: u64,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
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
    /// halt/start rewinds
    SetRewindStatus {
        /// true if rewind should be halted
        halt: bool,
    },
    /// set cooldown period
    SetCooldown {
        /// new cooldown period for rewind
        cooldown: u64,
    },
    /// attempt to rewind a skull's trait(s)
    Rewind {
        /// token id of the skull
        token_id: String,
    },
    /// set the viewing key with an svg server contract
    SetKeyWithServer {
        /// svg server code hash and address
        svg_server: ContractInfo,
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
    // response from setting a viewing key with an svg server
    SetKeyWithServer {
        status: String,
    },
    /// response of changing the rewind status
    SetRewindStatus {
        /// true if rewind has halted
        rewind_has_halted: bool,
    },
    RevokePermit {
        status: String,
    },
    /// response of attempting a rewind
    Rewind {
        /// the trait categories rewound
        categories_rewound: Vec<String>,
    },
    /// response from setting cooldown period
    SetCooldown {
        /// cooldown period
        cooldown: u64,
    },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the rewind status
    RewindStatus {},
    /// display the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the nft contract information
    NftContract {},
    /// display the cooldown period
    Cooldown {},
    /// display the times tokens were last rewound
    LastRewindTimes {
        /// list of token IDs
        token_ids: Vec<String>,
        /// optional address and viewing key of an owner
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify owner identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// displays the admins list
    Admins {
        /// current admin list
        admins: Vec<HumanAddr>,
    },
    /// displays the rewind status
    RewindStatus {
        /// true if rewind has halted
        rewind_has_halted: bool,
    },
    /// displays cooldown period
    Cooldown {
        /// cooldown period for rewinds
        cooldown: u64,
    },
    /// displays the nft contract information
    NftContract { nft_contract: ContractInfo },
    /// displays times of last rewind
    LastRewindTimes {
        /// list of last rewind times
        last_rewinds: Vec<TokenTime>,
    },
}

/// timestamps associated with tokens
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct TokenTime {
    /// token the timestamp corresponds to
    pub token_id: String,
    /// optional timestamp in seconds since 01/01/1970
    pub timestamp: Option<u64>,
}
