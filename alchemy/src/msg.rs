use crate::contract_info::ContractInfo;
use crate::snip721::Metadata;
use cosmwasm_std::{Addr, Binary, Uint128};
use schemars::JsonSchema;
use secret_toolkit::permit::Permit;
use serde::{Deserialize, Serialize};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InstantiateMsg {
    /// optional addresses to add as admins in addition to the instantiator
    pub admins: Option<Vec<String>>,
    /// entropy used for prng seed
    pub entropy: String,
    /// code hash and address of the svg server
    pub svg_server: ContractInfo,
    /// code hash and address of the skulls contract
    pub skulls_contract: ContractInfo,
    /// code hash and address of a crate contract
    pub crate_contract: ContractInfo,
    /// number of seconds to earn a staking charge (604800 for prod)
    pub charge_time: u64,
}

/// Handle messages
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// claim staking rewards
    ClaimStake {},
    /// set the staking list
    SetStake {
        /// list of skull token ids to stake (up to 5)
        token_ids: Vec<String>,
    },
    /// remove ingredients from a user's inventory to mint an nft containing them
    CrateIngredients { ingredients: Vec<IngredientQty> },
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
        admins: Vec<String>,
    },
    /// allows an admin to remove admin addresses
    RemoveAdmins {
        /// list of address to revoke admin priveleges from
        admins: Vec<String>,
    },
    /// retrieve info about skull types from the svg server
    GetSkullTypeInfo {},
    /// add ingredients
    AddIngredients { ingredients: Vec<String> },
    /// create named sets of ingredients for staking tables
    DefineIngredientSets { sets: Vec<IngredientSet> },
    /// create staking tables for specified skull materials
    SetStakingTables { tables: Vec<StakingTable> },
    /// set halt status for staking, crating, and/or alchemy
    SetHaltStatus {
        /// optionally set staking halt status
        staking: Option<bool>,
        /// optionally set alchemy halt status
        alchemy: Option<bool>,
        /// optionally set crating halt status
        crating: Option<bool>,
    },
    /// set charging time for staking
    SetChargeTime {
        /// number of seconds to earn a staking charge (604800 for prod)
        charge_time: u64,
    },
    /// set addresses and code hashes for used contracts
    SetContractInfos {
        /// optional code hash and address of the svg server
        svg_server: Option<ContractInfo>,
        /// optional code hash and address of the skulls contract
        skulls_contract: Option<ContractInfo>,
        /// optional crating contract (can either update the code hash of an existing one or add a new one)
        crate_contract: Option<ContractInfo>,
    },
    /// set the crate nft base metadata
    SetCrateMetadata { public_metadata: Metadata },
    /// BatchReceiveNft is called when this contract is sent an NFT (potion or crate)
    BatchReceiveNft {
        /// address of the previous owner of the token being sent
        from: String,
        /// list of tokens sent
        token_ids: Vec<String>,
        /// base64 encoded msg to specify the skull the potion should be applied to (if applicable)
        msg: Option<Binary>,
    },
    /// ReceiveNft is only included to maintatin CW721 compliance.  Hopefully everyone uses the
    /// superior BatchReceiveNft process.  ReceiveNft is called when this contract is sent an NFT
    /// (potion or crate)
    ReceiveNft {
        /// address of the previous owner of the token being sent
        sender: String,
        /// the token sent
        token_id: String,
        /// base64 encoded msg to specify the skull the potion should be applied to (if applicable)
        msg: Option<Binary>,
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
pub enum ExecuteAnswer {
    /// response from creating a viewing key
    ViewingKey { key: String },
    /// response from adding/removing admins
    AdminsList {
        /// current admins
        admins: Vec<Addr>,
    },
    /// response from adding ingredients
    AddIngredients {
        /// all known ingredients
        ingredients: Vec<String>,
    },
    /// response from creating named sets of ingredients for staking tables
    DefineIngredientSets {
        /// number of ingredient sets
        count: u8,
    },
    /// response from creating staking tables for specified skull materials
    SetStakingTables { status: String },
    /// response from setting halt status for staking, crating, and/or alchemy
    SetHaltStatus {
        /// true if staking is halted
        staking_is_halted: bool,
        /// true if alchemy is halted
        alchemy_is_halted: bool,
        /// true if crating is halted
        crating_is_halted: bool,
    },
    /// response from setting the crate nft base metadata
    SetCrateMetadata { public_metadata: Metadata },
    /// response from removing ingredients from a user's inventory to mint an nft containing them
    CrateIngredients {
        updated_inventory: Vec<IngredientQty>,
    },
    /// response from claiming or setting the staking list
    StakeInfo {
        /// charge info of the skulls currently staking
        charge_infos: Vec<ChargeInfo>,
        /// ingredients rewarded in this tx
        rewards: Vec<IngredientQty>,
    },
    /// response from setting charging time for staking
    SetChargeTime {
        /// number of seconds to earn a staking charge (604800 for prod)
        charge_time: u64,
    },
    /// response to setting addresses and code hashes for used contracts
    SetContractInfos {
        /// code hash and address of the svg server
        svg_server: ContractInfo,
        /// code hash and address of the skulls contract
        skulls_contract: ContractInfo,
        /// crate contracts
        crate_contracts: Vec<ContractInfo>,
    },
    /// response from revoking a permit
    RevokePermit { status: String },
}

/// Queries
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// displays the halt statuses for staking, crating, and alchemy
    HaltStatuses {},
    /// displays the staking, crating, and alchemy states
    States {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// lists the admin addresses
    Admins {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the code hashes and addresses of used contracts
    Contracts {},
    /// only displays a user's ingredients inventory (less intensive than MyStaking if you only
    /// need the inventory because it doesn't have to call the skulls contract to verify ownership
    /// of multiple skulls)
    MyIngredients {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays info about the skulls currently staked by the user and the ingredients they have
    /// in inventory
    MyStaking {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays if the user is eligible for a first time staking bonus
    UserEligibleForBonus {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays if the user and token list are eligible for a first time staking bonus
    TokensEligibleForBonus {
        /// optional address and viewing key of a user
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify user identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// list of token ids to check
        token_ids: Vec<String>,
    },
    /// displays the skull materials and indices
    Materials {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
    },
    /// displays the ingredients
    Ingredients {},
    /// displays the ingredient sets
    IngredientSets {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optional page number to display.  Defaults to 0 (first page) if not provided
        page: Option<u16>,
        /// optional limit to the number of ingredient sets to show.  Defaults to 30 if not specified
        page_size: Option<u16>,
    },
    /// displays the staking table for a specified skull material
    StakingTable {
        /// optional address and viewing key of an admin
        viewer: Option<ViewerInfo>,
        /// optional permit used to verify admin identity.  If both viewer and permit
        /// are provided, the viewer will be ignored
        permit: Option<Permit>,
        /// optionally display by the material name
        by_name: Option<String>,
        /// optionally display by the material index
        by_index: Option<u8>,
    },
}

/// responses to queries
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    /// displays if the user and token list are eligible for a first time staking bonus
    TokensEligibleForBonus {
        /// true if the user is eligible for the first time staking bonus
        user_is_eligible: bool,
        /// eligibility statuses for the requested tokens
        token_eligibility: Vec<EligibilityInfo>,
    },
    /// displays if the user is eligible for a first time staking bonus
    UserEligibleForBonus { is_eligible: bool },
    /// displays the halt statuses for staking, crating, and alchemy
    HaltStatuses {
        /// true if staking has been halted
        staking_is_halted: bool,
        /// true if alchemy has been halted
        alchemy_is_halted: bool,
        /// true if crating has been halted
        crating_is_halted: bool,
    },
    /// response listing the current admins
    Admins { admins: Vec<Addr> },
    /// displays the staking, crating, and alchemy states
    States {
        staking_state: StakingState,
        alchemy_state: AlchemyState,
        crating_state: DisplayCrateState,
    },
    /// displays the code hashes and addresses of used contracts
    Contracts {
        /// code hash and address of the svg server
        svg_server: ContractInfo,
        /// code hash and address of the skulls contract
        skulls_contract: ContractInfo,
        /// crate contracts
        crate_contracts: Vec<ContractInfo>,
    },
    /// displays the ingredients
    Ingredients { ingredients: Vec<String> },
    /// displays info about the skulls currently staked by the user and the ingredients they have
    /// in inventory
    MyStaking {
        /// true if the user is eligible for the first staking bonus
        first_stake_bonus_available: bool,
        /// charge info of the skulls currently staking
        charge_infos: Vec<ChargeInfo>,
        /// user's ingredient inventory
        inventory: Vec<IngredientQty>,
        /// true if staking is halted (so getting empty arrays for charges)
        staking_is_halted: bool,
    },
    /// only displays a user's ingredients inventory (less intensive than MyStaking if you only
    /// need the inventory because it doesn't have to call the skulls contract to verify ownership
    /// of multiple skulls)
    MyIngredients {
        /// user's ingredient inventory
        inventory: Vec<IngredientQty>,
    },
    /// displays the skull materials and indices
    Materials { materials: Vec<VariantIdxName> },
    /// displays the ingredient sets
    IngredientSets { ingredient_sets: Vec<IngredientSet> },
    /// displays the staking table for a specified skull material
    StakingTable { staking_table: StakingTable },
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct ViewerInfo {
    /// querying address
    pub address: String,
    /// authentication key string
    pub viewing_key: String,
}

/// set of ingredients for the staking tables
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct IngredientSet {
    /// name of the set
    pub name: String,
    /// list of ingredients in this set
    pub members: Vec<String>,
}

/// ingredient sets and their staking weight
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct IngrSetWeight {
    /// name of the set
    pub ingredient_set: String,
    /// weight
    pub weight: u16,
}

/// staking chances of ingredient sets and their weights for a specified skull material
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct StakingTable {
    /// skull material that uses this table
    pub material: String,
    /// ingredient sets and their weights
    pub ingredient_set_weights: Vec<IngrSetWeight>,
}

/// a skull's token id and info about its accrued charges
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct ChargeInfo {
    /// token id fo the skull
    pub token_id: String,
    /// timestamp for beginning of unclaimed charge
    pub charge_start: u64,
    /// whole number of charges accrued since charge_start (game cap at 4)
    pub charges: u8,
}

/// an ingredient and its quantity
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct IngredientQty {
    /// name of the ingredient
    pub ingredient: String,
    /// quantity of this ingredient
    pub quantity: u32,
}

/// info about staking state
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct StakingState {
    /// true if staking is halted
    pub halt: bool,
    /// skull category index
    pub skull_idx: u8,
    /// cooldown period
    pub cooldown: u64,
}

/// info about alchemy state
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct AlchemyState {
    /// true if alchemy is halted
    pub halt: bool,
    /// StoredLayerId for cyclops
    pub cyclops: StoredLayerId,
    /// StoredLayerId for jawless
    pub jawless: StoredLayerId,
}

/// displayable info about crating state
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct DisplayCrateState {
    /// true if crating is halted
    pub halt: bool,
    /// number of crates created
    pub cnt: Uint128,
}

/// identifies a layer
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct LayerId {
    /// the layer category name
    pub category: String,
    /// the variant name
    pub variant: String,
}

/// identifies a layer by indices
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct StoredLayerId {
    /// the layer category
    pub category: u8,
    pub variant: u8,
}

/// first time staking bonus eligibility for a token
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct EligibilityInfo {
    /// token id
    pub token_id: String,
    /// if token is owned by the user, true if the token is eligible for the bonus
    pub is_eligible: Option<bool>,
    /// if token is owned by the user AND it is not eligible, the time it was last claimed
    pub claimed_at: Option<u64>,
}

/// a variant's index and display name
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
pub struct VariantIdxName {
    /// index of the variant
    pub idx: u8,
    /// display name of the variant
    pub name: String,
}
