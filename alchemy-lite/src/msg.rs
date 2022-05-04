use crate::contract_info::ContractInfo;
use cosmwasm_std::{Binary, HumanAddr};
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
    /// optional definition of a potion
    pub potion: Option<PotionInfo>,
    /// optional list of potion contracts that might call
    pub potion_contracts: Option<Vec<ContractInfo>>,
    /// optional list of svg server contracts to set viewing key with
    pub svg_servers: Option<Vec<ContractInfo>>,
    /// entropy used for prng seed
    pub entropy: String,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// adds a new potion or modifies an existing potion
    SetPotion { potion: PotionInfo },
    /// add potion and/or svg server contracts
    AddContracts {
        /// optional potion contracts to add
        potion_contracts: Option<Vec<ContractInfo>>,
        /// optional svg server contracts to add
        svg_servers: Option<Vec<ContractInfo>>,
    },
    /// list of potion contracts to stop accepting NFTs from
    RemovePotionContracts {
        /// list of potions contracts to stop accepting
        potion_contracts: Vec<HumanAddr>,
    },
    /// BatchReceiveNft is called by the potion contract to apply a potion to a skull
    BatchReceiveNft {
        /// address of the potion owner
        from: HumanAddr,
        /// list of potions sent (only allowing one at a time)
        token_ids: Vec<String>,
        /// base64 encoded msg to specify the token_id of the skull to apply the potion to
        msg: Option<Binary>,
    },
    /// ReceiveNft is only included to maintatin CW721 compliance.  Hopefully everyone uses the
    /// superior BatchReceiveNft process.  ReceiveNft is called by the NFT contract to claim a potion
    /// using the sent NFT
    ReceiveNft {
        /// address of the owner of the token being used to claim
        sender: HumanAddr,
        /// the token sent (used to claim)
        token_id: String,
        /// base64 encoded msg to specify the token_id of the skull to apply the potion to
        msg: Option<Binary>,
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
    /// set the halt status of either the contract or a specific potion
    SetHaltStatus {
        /// optionally only alter halt status of one potion.  Halt entire contract if the potion
        /// is not specified
        potion: Option<String>,
        /// true if should be halted
        halt: bool,
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
    /// response of setting halt status
    SetHaltStatus {
        /// name of the single potion whose status was set, if applicable
        potion: Option<String>,
        /// true if halted
        halted: bool,
    },
    /// response of adding potion and svg server contracts
    AddContracts {
        /// potion contracts
        potion_contracts: Vec<ContractInfo>,
        /// svg server contracts
        svg_servers: Vec<ContractInfo>,
    },
    /// response from removing potion contracts
    RemovePotionContracts {
        /// potion contracts
        potion_contracts: Vec<ContractInfo>,
    },
    /// response from adding/modifying a potion
    SetPotion {
        /// number of potions this contract processes
        count: u16,
        /// true if updating an existing potion
        updated_existing: bool,
    },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the potion contracts
    PotionContracts {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display the svg server contracts
    SvgServers {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// display a list of potion names and their indices
    Potions {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page
        page: Option<u16>,
        /// optional max number of potion IDs to display (defaults to 100)
        page_size: Option<u16>,
    },
    /// display the definition of the specified potion
    PotionInfo {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional name of the potion to display
        name: Option<String>,
        /// optional index of the potion to display.  If neither name nor index is provided, the
        /// query will throw an error
        index: Option<u16>,
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
    /// list of potion contracts
    PotionContracts { potion_contracts: Vec<ContractInfo> },
    /// list of svg servers
    SvgServers { svg_servers: Vec<ContractInfo> },
    /// list potion names and indices
    Potions {
        /// total count of potions
        count: u16,
        /// potions' names and indices
        potions: Vec<PotionNameIdx>,
    },
    /// display the definition of a potion
    PotionInfo {
        /// true if the potion has been halted
        halted: bool,
        potion: PotionInfo,
    },
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}

/// identifies a layer
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct LayerId {
    /// the layer category name
    pub category: String,
    /// the variant name
    pub variant: String,
}

/// trait variant information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct VariantInfo {
    /// layers that compose this variant
    pub layers: Vec<LayerId>,
    /// randomization weight for this trait variant if skull has 2 eyes and a jaw
    pub normal_weight: u16,
    /// randomization weight for this variant if jawless
    pub jawless_weight: Option<u16>,
    /// randomization weight for cyclops
    pub cyclops_weight: Option<u16>,
}

/// potion information
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct PotionInfo {
    /// potion name
    pub name: String,
    /// optional potion contract if this will be hosted by one not already added
    pub potion_contract: Option<ContractInfo>,
    /// svg server the potion uses
    pub svg_server: ContractInfo,
    /// possible traits and their weights
    pub variants: Vec<VariantInfo>,
}

/// potion name and index
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct PotionNameIdx {
    /// potion name
    pub name: String,
    /// potion's index
    pub index: u16,
}
