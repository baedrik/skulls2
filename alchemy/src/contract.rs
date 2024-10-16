use base64::{engine::general_purpose, Engine as _};
use rand::seq::SliceRandom;
use rand_core::RngCore;

use cosmwasm_std::{
    entry_point, to_binary, Addr, Api, Binary, CanonicalAddr, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, Response, StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    crypto::{sha_256, ContractPrng},
    permit::{validate, Permit, RevokedPermits},
    utils::{pad_handle_result, pad_query_result, HandleCallback, Query},
    viewing_key::{ViewingKey, ViewingKeyStore},
};

use crate::contract_info::{ContractInfo, StoreContractInfo};
use crate::msg::{
    AlchemyState, ChargeInfo, EligibilityInfo, ExecuteAnswer, ExecuteMsg, IngrSetWeight,
    IngredientQty, IngredientSet, InstantiateMsg, QueryAnswer, QueryMsg, SelfHandleMsg,
    StakingState, StakingTable, StoredLayerId, VariantIdxName, ViewerInfo,
};
use crate::server_msgs::{ServerQueryMsg, SkullTypePlusWrapper};
use crate::snip721::{ImageInfo, ImageInfoWrapper, Snip721HandleMsg, Snip721QueryMsg};
use crate::state::{
    SkullStakeInfo, StoredIngrSet, StoredSetWeight, ADMINS_KEY, ALCHEMY_STATE_KEY, CRATES_KEY,
    INGREDIENTS_KEY, INGRED_SETS_KEY, MATERIALS_KEY, MY_VIEWING_KEY, PREFIX_REVOKED_PERMITS,
    PREFIX_SKULL_STAKE, PREFIX_STAKING_TABLE, PREFIX_USER_INGR_INVENTORY, PREFIX_USER_STAKE,
    SKULL_721_KEY, STAKING_STATE_KEY, SVG_SERVER_KEY,
};
use crate::storage::{load, may_load, save};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Instantiate ///////////////////////////////////////
/// Returns StdResult<Response>
///
/// Initializes the alchemy contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `info` - calling message information MessageInfo
/// * `msg` - InstantiateMsg passed in with the instantiation message
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let sender_raw = deps.api.addr_canonicalize(info.sender.as_str())?;
    let prng_seed = sha_256(
        general_purpose::STANDARD
            .encode(msg.entropy.as_str())
            .as_bytes(),
    );
    ViewingKey::set_seed(deps.storage, &prng_seed);
    let key = ViewingKey::create(
        deps.storage,
        &info,
        &env,
        info.sender.as_str(),
        msg.entropy.as_ref(),
    );
    save(deps.storage, MY_VIEWING_KEY, &key)?;
    let mut admins = vec![sender_raw];
    if let Some(addrs) = msg.admins {
        add_addrs_to_auth(deps.api, &mut admins, &addrs)?;
    }
    save(deps.storage, ADMINS_KEY, &admins)?;
    let svg_addr = deps
        .api
        .addr_validate(&msg.svg_server.address)
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
    let svg_raw = StoreContractInfo {
        address: svg_addr,
        code_hash: msg.svg_server.code_hash,
    };
    save(deps.storage, SVG_SERVER_KEY, &svg_raw)?;
    let skull_addr = deps
        .api
        .addr_validate(&msg.skulls_contract.address)
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
    let skull_raw = StoreContractInfo {
        address: skull_addr,
        code_hash: msg.skulls_contract.code_hash,
    };
    save(deps.storage, SKULL_721_KEY, &skull_raw)?;
    let crates = vec![msg.crate_contract.into_store(deps.api)?];
    save(deps.storage, CRATES_KEY, &crates)?;
    let stk_st = StakingState {
        halt: true,
        skull_idx: 2,
        cooldown: msg.charge_time,
    };
    save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
    let alc_st = AlchemyState {
        halt: true,
        cyclops: StoredLayerId {
            category: 5,
            variant: 1,
        },
        jawless: StoredLayerId {
            category: 3,
            variant: 0,
        },
    };
    save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
    let messages = vec![
        Snip721HandleMsg::SetViewingKey { key: key.clone() }.to_cosmos_msg(
            svg_raw.code_hash,
            msg.svg_server.address,
            None,
        )?,
        Snip721HandleMsg::SetViewingKey { key }.to_cosmos_msg(
            skull_raw.code_hash,
            msg.skulls_contract.address,
            None,
        )?,
        SelfHandleMsg::GetSkullTypeInfo {}.to_cosmos_msg(
            env.contract.code_hash,
            env.contract.address.into_string(),
            None,
        )?,
    ];

    Ok(Response::new().add_messages(messages))
}

///////////////////////////////////// Execute //////////////////////////////////////
/// Returns StdResult<Response>
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `info` - calling message information MessageInfo
/// * `msg` - ExecuteMsg passed in with the execute message
#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let response = match msg {
        ExecuteMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &info, &entropy),
        ExecuteMsg::SetViewingKey { key, .. } => try_set_key(deps, &info.sender, key),
        ExecuteMsg::AddAdmins { admins } => {
            try_process_auth_list(deps, &info.sender, &admins, true)
        }
        ExecuteMsg::RemoveAdmins { admins } => {
            try_process_auth_list(deps, &info.sender, &admins, false)
        }
        ExecuteMsg::GetSkullTypeInfo {} => try_get_skull_info(deps, &info.sender, env),
        ExecuteMsg::AddIngredients { ingredients } => {
            try_add_ingredients(deps, &info.sender, ingredients)
        }
        ExecuteMsg::SetStakingTables { tables } => try_stake_tbl(deps, &info.sender, tables),
        ExecuteMsg::DefineIngredientSets { sets } => try_set_ingred_set(deps, &info.sender, sets),
        ExecuteMsg::SetHaltStatus { staking, alchemy } => {
            try_set_halt(deps, &info.sender, staking, alchemy)
        }
        ExecuteMsg::SetStake { token_ids } => try_set_stake(deps, env, &info.sender, token_ids),
        ExecuteMsg::ClaimStake {} => try_claim_stake(deps, env, &info.sender),
        ExecuteMsg::SetChargeTime { charge_time } => {
            try_set_charge_time(deps, &info.sender, charge_time)
        }
        ExecuteMsg::SetContractInfos {
            svg_server,
            skulls_contract,
            crate_contract,
        } => try_set_contracts(
            deps,
            &info.sender,
            svg_server,
            skulls_contract,
            crate_contract,
        ),
        ExecuteMsg::RevokePermit { permit_name } => {
            revoke_permit(deps.storage, &info.sender, &permit_name)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns StdResult<Response>
///
/// claim staking rewards for a user
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - the Env of contract's environment
/// * `sender` - a reference to the message sender
fn try_claim_stake(deps: DepsMut, env: Env, sender: &Addr) -> StdResult<Response> {
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    if stk_state.halt {
        return Err(StdError::generic_err("Staking has been halted"));
    }
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let user_key = user_raw.as_slice();
    // get staking list and only keep the ones the user still owns
    let old_list = may_load::<Vec<String>>(&user_store, user_key)?
        .ok_or_else(|| StdError::generic_err("You have never started staking"))?;
    if old_list.is_empty() {
        return Err(StdError::generic_err("You are not staking any skulls"));
    }
    let (id_images, _) = verify_ownership(
        deps.as_ref(),
        sender.as_str(),
        old_list,
        env.contract.address.to_string(),
    )?;
    if id_images.is_empty() {
        return Err(StdError::generic_err(
            "You no longer own any of the skulls you were staking",
        ));
    }
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
    let mut charges: Vec<u8> = vec![0; materials.len()];
    let mut quantities: Vec<u8> = charges.clone();
    let mut charge_infos: Vec<ChargeInfo> = Vec::new();
    let mut new_list: Vec<String> = Vec::new();
    let now = env.block.time.seconds();
    let mut skull_store = PrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
    for id_img in id_images.into_iter() {
        let id_key = id_img.id.as_bytes();
        let mut stk_inf =
            may_load::<SkullStakeInfo>(&skull_store, id_key)?.unwrap_or(SkullStakeInfo {
                addr: user_raw.clone(),
                stake: now,
                claim: 0,
            });
        // can't claim skulls that are staking with a different user now
        if stk_inf.addr != user_raw {
            continue;
        }
        let time_in_stake = now - stk_inf.stake;
        // tally accrued charges
        let charge_cnt = min(4, time_in_stake / stk_state.cooldown) as u8;
        // if this skull has charge
        if charge_cnt > 0 {
            // tally skull materials
            quantities[id_img.image.natural[stk_state.skull_idx as usize] as usize] += 1;
            charges[id_img.image.natural[stk_state.skull_idx as usize] as usize] += charge_cnt;
            let time_of_maturity = now - (time_in_stake % stk_state.cooldown);
            stk_inf.stake = time_of_maturity;
            stk_inf.claim = time_of_maturity;
            save(&mut skull_store, id_key, &stk_inf)?;
        }
        new_list.push(id_img.id.clone());
        charge_infos.push(ChargeInfo {
            token_id: id_img.id,
            charge_start: stk_inf.stake,
            charges: 0,
        });
    }
    let mut user_store = PrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    save(&mut user_store, user_key, &new_list)?;
    let rewards: Vec<IngredientQty> = if charges.iter().any(|i| *i > 0) {
        process_charges(deps.storage, &env, &charges, &quantities, user_key)?
    } else {
        return Err(StdError::generic_err(
            "None of your staked skulls have charges",
        ));
    };

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::StakeInfo {
            charge_infos,
            rewards,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// set the staking inventory for a user
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - the Env of contract's environment
/// * `sender` - a reference to the message sender
/// * `token_ids` - list of skull ids to stake
fn try_set_stake(
    deps: DepsMut,
    env: Env,
    sender: &Addr,
    token_ids: Vec<String>,
) -> StdResult<Response> {
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    if stk_state.halt {
        return Err(StdError::generic_err("Staking has been halted"));
    }
    let skull_cnt = token_ids.len();
    // check if staking an appropriate number
    if skull_cnt > 5 {
        return Err(StdError::generic_err("You can only stake up to 5 skulls"));
    }
    // check if sender owns all the skulls they are trying to stake
    let (id_images, not_owned) = verify_ownership(
        deps.as_ref(),
        sender.as_str(),
        token_ids,
        env.contract.address.to_string(),
    )?;
    if !not_owned.is_empty() {
        // error out if any or not owned
        let mut err_str = "You do not own skull(s): ".to_string();
        let mut first_id = true;
        for id in not_owned.iter() {
            if !first_id {
                err_str.push_str(", ");
            }
            err_str.push_str(id);
            first_id = false;
        }
        return Err(StdError::generic_err(err_str));
    }
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_raw = deps.api.addr_canonicalize(sender.as_str())?;
    let user_key = user_raw.as_slice();
    let do_claim = may_load::<Vec<String>>(&user_store, user_key)?.is_none();
    // if they never started claiming, but sent an empty list
    if do_claim && skull_cnt == 0 {
        return Err(StdError::generic_err(
            "Do not waste your First-Stake reward by initializing an empty staking inventory",
        ));
    }
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
    let mut charges: Vec<u8> = vec![0; materials.len()];
    let mut charge_infos: Vec<ChargeInfo> = Vec::new();
    let mut stk_list: Vec<String> = Vec::new();
    let now = env.block.time.seconds();
    let cutoff = now - stk_state.cooldown;
    let mut skull_store = PrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
    for id_img in id_images.into_iter() {
        let id_key = id_img.id.as_bytes();
        let mut stk_inf =
            may_load::<SkullStakeInfo>(&skull_store, id_key)?.unwrap_or(SkullStakeInfo {
                addr: user_raw.clone(),
                stake: now,
                claim: 0,
            });
        // generate resources if first time user has staked
        // don't allow a first stake reward to be given out for skulls that have been claimed within 1 cooldown
        if do_claim && stk_inf.claim <= cutoff {
            charges[id_img.image.natural[stk_state.skull_idx as usize] as usize] += 1;
            stk_inf.claim = now;
        }
        // if user has not been staking this skull
        if stk_inf.addr != user_raw {
            stk_inf.addr = user_raw.clone();
            stk_inf.stake = now;
        }
        save(&mut skull_store, id_key, &stk_inf)?;
        stk_list.push(id_img.id.clone());
        charge_infos.push(ChargeInfo {
            token_id: id_img.id,
            charge_start: stk_inf.stake,
            charges: min(4, (now - stk_inf.stake) / stk_state.cooldown) as u8,
        });
    }
    let mut user_store = PrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    save(&mut user_store, user_key, &stk_list)?;
    let rewards: Vec<IngredientQty> = if charges.iter().any(|i| *i > 0) {
        process_charges(deps.storage, &env, &charges, &charges, user_key)?
    } else if do_claim {
        return Err(StdError::generic_err("All skulls being staked have not cooled down long enough and are not eligible for First-Stake rewards and would waste this one time offer"));
    } else {
        Vec::new()
    };

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::StakeInfo {
            charge_infos,
            rewards,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// set code hashes and addresses of used contracts
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `new_svg_server` - optional code hash and address of the svg server
/// * `new_skulls_contract` - optional code hash and address of the skulls contract
/// * `new_crate_contract` - optional code hash and address of a crating contract (can either update the code
///                     hash of an existing one or add a new one)
fn try_set_contracts(
    deps: DepsMut,
    sender: &Addr,
    new_svg_server: Option<ContractInfo>,
    new_skulls_contract: Option<ContractInfo>,
    new_crate_contract: Option<ContractInfo>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut messages: Vec<CosmosMsg> = Vec::new();
    let key: String = load(deps.storage, MY_VIEWING_KEY)?;

    let svg_server = if let Some(svg) = new_svg_server {
        let raw = svg.get_store(deps.api)?;
        messages.push(
            Snip721HandleMsg::SetViewingKey { key: key.clone() }.to_cosmos_msg(
                svg.code_hash.clone(),
                svg.address.clone(),
                None,
            )?,
        );
        save(deps.storage, SVG_SERVER_KEY, &raw)?;
        svg
    } else {
        load::<StoreContractInfo>(deps.storage, SVG_SERVER_KEY)
            .and_then(|s| s.into_humanized(deps.api))?
    };
    let skulls_contract = if let Some(skl) = new_skulls_contract {
        let raw = skl.get_store(deps.api)?;
        messages.push(Snip721HandleMsg::SetViewingKey { key }.to_cosmos_msg(
            skl.code_hash.clone(),
            skl.address.clone(),
            None,
        )?);
        save(deps.storage, SKULL_721_KEY, &raw)?;
        skl
    } else {
        load::<StoreContractInfo>(deps.storage, SKULL_721_KEY)
            .and_then(|s| s.into_humanized(deps.api))?
    };
    let mut raw_crates: Vec<StoreContractInfo> = load(deps.storage, CRATES_KEY)?;
    if let Some(crt) = new_crate_contract {
        let raw = crt.into_store(deps.api)?;
        if let Some(old) = raw_crates.iter_mut().find(|c| c.address == raw.address) {
            old.code_hash = raw.code_hash;
        } else {
            raw_crates.push(raw);
        }
        save(deps.storage, CRATES_KEY, &raw_crates)?;
    }

    let mut resp = Response::new();
    if !messages.is_empty() {
        resp = resp.add_messages(messages);
    }
    Ok(resp.set_data(to_binary(&ExecuteAnswer::SetContractInfos {
        svg_server,
        skulls_contract,
        crate_contracts: raw_crates
            .into_iter()
            .map(|s| s.into_humanized(deps.api))
            .collect::<StdResult<Vec<ContractInfo>>>()?,
    })?))
}

/// Returns StdResult<Response>
///
/// set the staking charge time
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `charge_time` - staking charge time in seconds
fn try_set_charge_time(deps: DepsMut, sender: &Addr, charge_time: u64) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut stk_st: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    if stk_st.cooldown != charge_time {
        stk_st.cooldown = charge_time;
        save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetChargeTime {
            charge_time: stk_st.cooldown,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// set the halt status of staking and/or alchemy
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `staking` - optionally set staking halt status
/// * `alchemy` - optionally set alchemy halt status
fn try_set_halt(
    deps: DepsMut,
    sender: &Addr,
    staking: Option<bool>,
    alchemy: Option<bool>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut stk_st: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    // if setting staking halt status
    if let Some(stk) = staking {
        // if it would change
        if stk_st.halt != stk {
            stk_st.halt = stk;
            // if enabling staking
            if !stk_st.halt {
                let materials: Vec<String> =
                    may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
                if materials.is_empty() {
                    return Err(StdError::generic_err("Skull materials are undefined"));
                }
                // check if all materials have a staking table
                let tbl_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_STAKING_TABLE);
                for (i, mat) in materials.into_iter().enumerate() {
                    let i_sml = i as u8;
                    if may_load::<Vec<StoredSetWeight>>(&tbl_store, &i_sml.to_le_bytes())?.is_none()
                    {
                        return Err(StdError::generic_err(format!(
                            "{} staking table has not been defined",
                            mat
                        )));
                    }
                }
            }
            save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
        }
    }
    // if setting alchemy halt status
    if let Some(alc) = alchemy {
        if alc_st.halt != alc {
            alc_st.halt = alc;
            save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;
        }
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetHaltStatus {
            staking_is_halted: stk_st.halt,
            alchemy_is_halted: alc_st.halt,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// define the staking tables
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `tables` - list of ingredient sets and their weights for specified materials
fn try_stake_tbl(deps: DepsMut, sender: &Addr, tables: Vec<StakingTable>) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();

    for tbl in tables.into_iter() {
        let mut weights: Vec<StoredSetWeight> = Vec::new();
        let mat = if let Some(pos) = materials.iter().position(|m| *m == tbl.material) {
            pos as u8
        } else {
            return Err(StdError::generic_err(format!(
                "{} is not a known skull material",
                tbl.material
            )));
        };
        let mat_key = mat.to_le_bytes();
        for st_wt in tbl.ingredient_set_weights.into_iter() {
            let set = if let Some(set_pos) = ingr_sets
                .iter()
                .position(|s| s.name == st_wt.ingredient_set)
            {
                set_pos as u8
            } else {
                return Err(StdError::generic_err(format!(
                    "{} is not a known IngredientSet",
                    st_wt.ingredient_set
                )));
            };
            if weights.iter().any(|w| w.set == set) {
                return Err(StdError::generic_err(format!(
                    "{} has been duplicated in the staking table",
                    st_wt.ingredient_set
                )));
            }
            weights.push(StoredSetWeight {
                set,
                weight: st_wt.weight,
            });
        }
        let mut tbl_store = PrefixedStorage::new(deps.storage, PREFIX_STAKING_TABLE);
        save(&mut tbl_store, &mat_key, &weights)?;
    }
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetStakingTables {
            status: "success".to_string(),
        })?),
    )
}

/// Returns StdResult<Response>
///
/// define ingredients sets for staking tables
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `sets` - list of ingredient sets
fn try_set_ingred_set(
    deps: DepsMut,
    sender: &Addr,
    sets: Vec<IngredientSet>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let mut ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();
    for set in sets.into_iter() {
        let mut list: Vec<u8> = Vec::new();
        for member in set.members.iter() {
            if let Some(pos) = ingredients.iter().position(|ing| ing == member) {
                let pos8 = pos as u8;
                if !list.contains(&pos8) {
                    list.push(pos8);
                }
            } else {
                return Err(StdError::generic_err(format!(
                    "{} is not a known ingredient",
                    member
                )));
            }
        }
        if let Some(old_set) = ingr_sets.iter_mut().find(|s| s.name == set.name) {
            old_set.list = list;
        } else {
            ingr_sets.push(StoredIngrSet {
                name: set.name,
                list,
            });
        }
    }
    save(deps.storage, INGRED_SETS_KEY, &ingr_sets)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::DefineIngredientSets {
            count: ingr_sets.len() as u8,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// add ingredient names
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `ingr_to_add` - list of ingredient names to add
fn try_add_ingredients(
    deps: DepsMut,
    sender: &Addr,
    ingr_to_add: Vec<String>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;
    let mut ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();
    for ingr in ingr_to_add.into_iter() {
        if !ingredients.contains(&ingr) {
            ingredients.push(ingr);
        }
    }
    save(deps.storage, INGREDIENTS_KEY, &ingredients)?;
    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::AddIngredients { ingredients })?))
}

/// Returns StdResult<Response>
///
/// get skull type and material info from the svg server
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `env` - Env of contract's environment
fn try_get_skull_info(deps: DepsMut, sender: &Addr, env: Env) -> StdResult<Response> {
    // see if self-called
    if *sender != env.contract.address {
        // if not, only allow admins to do this
        check_admin_tx(deps.as_ref(), sender)?;
    }
    let svg_server = load::<StoreContractInfo>(deps.storage, SVG_SERVER_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;
    let viewing_key: String = load(deps.storage, MY_VIEWING_KEY)?;
    let viewer = ViewerInfo {
        address: env.contract.address.into_string(),
        viewing_key,
    };
    let st_plus = ServerQueryMsg::SkullTypePlus { viewer }
        .query::<_, SkullTypePlusWrapper>(deps.querier, svg_server.code_hash, svg_server.address)?
        .skull_type_plus;
    let mut stk_st: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    stk_st.skull_idx = st_plus.skull_idx;
    save(deps.storage, STAKING_STATE_KEY, &stk_st)?;
    let mut alc_st: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;
    alc_st.cyclops = st_plus.cyclops;
    alc_st.jawless = st_plus.jawless;
    save(deps.storage, ALCHEMY_STATE_KEY, &alc_st)?;

    let mut materials = vec![String::new(); st_plus.skull_variants.len()];
    for idx_name in st_plus.skull_variants.into_iter() {
        materials[idx_name.idx as usize] = idx_name.name;
    }
    if materials.iter().any(|n| *n == String::new()) {
        return Err(StdError::generic_err("Blank Name in skull material list"));
    }
    save(deps.storage, MATERIALS_KEY, &materials)?;

    Ok(Response::default())
}

/// Returns StdResult<Response>
///
/// creates a viewing key
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `info` - calling message information MessageInfo
/// * `entropy` - string slice of the input String to be used as entropy in randomization
fn try_create_key(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    entropy: &str,
) -> StdResult<Response> {
    let key = ViewingKey::create(
        deps.storage,
        info,
        env,
        info.sender.as_str(),
        entropy.as_ref(),
    );
    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ViewingKey { key })?))
}

/// Returns StdResult<Response>
///
/// sets the viewing key to the input String
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `key` - String to be used as the viewing key
fn try_set_key(deps: DepsMut, sender: &Addr, key: String) -> StdResult<Response> {
    ViewingKey::set(deps.storage, sender.as_str(), &key);

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::ViewingKey { key })?))
}

/// Returns StdResult<Response>
///
/// revoke the ability to use a specified permit
///
/// # Arguments
///
/// * `storage` - mutable reference to the contract's storage
/// * `sender` - a reference to the message sender address
/// * `permit_name` - string slice of the name of the permit to revoke
fn revoke_permit(
    storage: &mut dyn Storage,
    sender: &Addr,
    permit_name: &str,
) -> StdResult<Response> {
    RevokedPermits::revoke_permit(
        storage,
        PREFIX_REVOKED_PERMITS,
        sender.as_str(),
        permit_name,
    );

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::RevokePermit {
            status: "success".to_string(),
        })?),
    )
}

/////////////////////////////////////// Query /////////////////////////////////////
/// Returns StdResult<Binary>
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - QueryMsg passed in with the query call
#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Admins { viewer, permit } => {
            query_admins(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::HaltStatuses {} => query_halt(deps.storage),
        QueryMsg::Contracts {} => query_contracts(deps),
        QueryMsg::MyStaking { viewer, permit } => query_my_stake(deps, env, viewer, permit),
        QueryMsg::MyIngredients { viewer, permit } => {
            query_my_inv(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::UserEligibleForBonus { viewer, permit } => {
            query_user_bonus(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::TokensEligibleForBonus {
            viewer,
            permit,
            token_ids,
        } => query_token_bonus(deps, env, viewer, permit, token_ids),
        QueryMsg::Materials { viewer, permit } => {
            query_mater(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::Ingredients {} => query_ingr(deps.storage),
        QueryMsg::IngredientSets {
            viewer,
            permit,
            page,
            page_size,
        } => query_ingr_sets(deps, viewer, permit, page, page_size, &env.contract.address),
        QueryMsg::StakingTable {
            viewer,
            permit,
            by_name,
            by_index,
        } => query_stk_tbl(
            deps,
            viewer,
            permit,
            by_name,
            by_index,
            &env.contract.address,
        ),
        QueryMsg::States { viewer, permit } => {
            query_state(deps, viewer, permit, &env.contract.address)
        }
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns StdResult<Binary> which displays staking and alchemy halt statuses
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
fn query_halt(storage: &dyn Storage) -> StdResult<Binary> {
    let stk_st: StakingState = load(storage, STAKING_STATE_KEY)?;
    let alc_st: AlchemyState = load(storage, ALCHEMY_STATE_KEY)?;

    to_binary(&QueryAnswer::HaltStatuses {
        staking_is_halted: stk_st.halt,
        alchemy_is_halted: alc_st.halt,
    })
}

/// Returns StdResult<Binary> which displays the code hashes and addresses
/// of used contract
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
fn query_contracts(deps: Deps) -> StdResult<Binary> {
    let svg_server = load::<StoreContractInfo>(deps.storage, SVG_SERVER_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;
    let skulls_contract = load::<StoreContractInfo>(deps.storage, SKULL_721_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;
    let crate_contracts =
        load::<Vec<StoreContractInfo>>(deps.storage, CRATES_KEY).and_then(|v| {
            v.into_iter()
                .map(|s| s.into_humanized(deps.api))
                .collect::<StdResult<Vec<ContractInfo>>>()
        })?;

    to_binary(&QueryAnswer::Contracts {
        svg_server,
        skulls_contract,
        crate_contracts,
    })
}

/// Returns StdResult<Binary> displaying the staking table for a specified skull material
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `by_name` - optional material string to display
/// * `by_index` - optional material index to display
/// * `my_addr` - a reference to this contract's address
fn query_stk_tbl(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    by_name: Option<String>,
    by_index: Option<u8>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let mut materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();
    let idx = if let Some(nm) = by_name {
        materials
            .iter()
            .position(|m| *m == nm)
            .ok_or_else(|| StdError::generic_err(format!("Unknown material: {}", nm)))?
            as u8
    } else {
        by_index.ok_or_else(|| StdError::generic_err("Must provide either a name or index"))?
    };
    let tbl_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_STAKING_TABLE);
    let tbl = may_load::<Vec<StoredSetWeight>>(&tbl_store, &idx.to_le_bytes())
        .and_then(|s| s.ok_or_else(|| StdError::generic_err("Invalid SetWeight index")))?;
    let ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::StakingTable {
        staking_table: StakingTable {
            material: materials.swap_remove(idx as usize),
            ingredient_set_weights: tbl
                .iter()
                .map(|s| IngrSetWeight {
                    ingredient_set: ingr_sets[s.set as usize].name.clone(),
                    weight: s.weight,
                })
                .collect::<Vec<IngrSetWeight>>(),
        },
    })
}

/// Returns StdResult<Binary> displaying the ingredient sets
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page to display
/// * `page_size` - optional number of sets to display
/// * `my_addr` - a reference to this contract's address
fn query_ingr_sets(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let ingr_sets: Vec<StoredIngrSet> =
        may_load(deps.storage, INGRED_SETS_KEY)?.unwrap_or_default();
    let ingredients: Vec<String> = may_load(deps.storage, INGREDIENTS_KEY)?.unwrap_or_default();

    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(30);
    let skip = (page * limit) as usize;

    to_binary(&QueryAnswer::IngredientSets {
        ingredient_sets: ingr_sets
            .into_iter()
            .skip(skip)
            .take(limit as usize)
            .map(|s| IngredientSet {
                name: s.name,
                members: s
                    .list
                    .iter()
                    .map(|u| ingredients[*u as usize].clone())
                    .collect::<Vec<String>>(),
            })
            .collect::<Vec<IngredientSet>>(),
    })
}

/// Returns StdResult<Binary> displaying the user's inventory of ingredients
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_my_inv(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    let (user_raw, _) = get_querier(deps, viewer, permit, my_addr)?;

    // retrieve the user's ingredient inventory
    let inventory = display_inventory(deps.storage, user_raw.as_slice())?;

    to_binary(&QueryAnswer::MyIngredients { inventory })
}

/// Returns StdResult<Binary> displaying whether the user is eligible for the first time staking bonus
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_user_bonus(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    let (user_raw, _) = get_querier(deps, viewer, permit, my_addr)?;
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);

    to_binary(&QueryAnswer::UserEligibleForBonus {
        is_eligible: may_load::<Vec<String>>(&user_store, user_raw.as_slice())?.is_none(),
    })
}

/// Returns StdResult<Binary> displaying first staking bonus eligibility for the user and
/// specified tokens
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `token_ids` - list of tokens to check
fn query_token_bonus(
    deps: Deps,
    env: Env,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    token_ids: Vec<String>,
) -> StdResult<Binary> {
    let (user_raw, user_hmn) = get_querier(deps, viewer, permit, &env.contract.address)?;
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_is_eligible = may_load::<Vec<String>>(&user_store, user_raw.as_slice())?.is_none();
    let mut token_eligibility: Vec<EligibilityInfo> = Vec::new();
    if user_is_eligible {
        let skull_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
        let (_, not_owned) = verify_ownership(
            deps,
            &user_hmn,
            token_ids.clone(),
            env.contract.address.into_string(),
        )?;
        let now = env.block.time.seconds();
        let cutoff = now - stk_state.cooldown;
        for token_id in token_ids.into_iter() {
            let (is_eligible, claimed_at) = if not_owned.contains(&token_id) {
                (None, None)
            } else {
                let stk_inf = may_load::<SkullStakeInfo>(&skull_store, token_id.as_bytes())?
                    .unwrap_or(SkullStakeInfo {
                        addr: CanonicalAddr::from(Binary::default()),
                        stake: 0,
                        claim: 0,
                    });
                let is_elg = stk_inf.claim <= cutoff;
                let claim = if is_elg { None } else { Some(stk_inf.claim) };
                (Some(is_elg), claim)
            };
            token_eligibility.push(EligibilityInfo {
                token_id,
                is_eligible,
                claimed_at,
            });
        }
    }

    to_binary(&QueryAnswer::TokensEligibleForBonus {
        user_is_eligible,
        token_eligibility,
    })
}

/// Returns StdResult<Binary> displaying the user's staking skulls and charges as well as
/// their inventory of ingredients
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_my_stake(
    deps: Deps,
    env: Env,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> StdResult<Binary> {
    let (user_raw, user_hmn) = get_querier(deps, viewer, permit, &env.contract.address)?;
    let stk_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let user_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_USER_STAKE);
    let user_key = user_raw.as_slice();
    // get staking list
    let may_stk_list = may_load::<Vec<String>>(&user_store, user_key)?;
    let first_stake_bonus_available = may_stk_list.is_none();
    let stk_list = may_stk_list.unwrap_or_default();
    // only show skulls the user still owns
    let id_images = if stk_state.halt {
        Vec::new()
    } else {
        let (idi, _) = verify_ownership(
            deps,
            &user_hmn,
            stk_list,
            env.contract.address.into_string(),
        )?;
        idi
    };
    let mut charge_infos: Vec<ChargeInfo> = Vec::new();
    let now = env.block.time.seconds();
    let skull_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_SKULL_STAKE);
    for id_img in id_images.into_iter() {
        // get staking info of each skull
        let id_key = id_img.id.as_bytes();
        let stk_inf = may_load::<SkullStakeInfo>(&skull_store, id_key)?.unwrap_or(SkullStakeInfo {
            addr: CanonicalAddr::from(Binary::default()),
            stake: 0,
            claim: 0,
        });
        // can't claim skulls that are staking with a different user now
        if stk_inf.addr != user_raw {
            continue;
        }
        let time_in_stake = now - stk_inf.stake;
        // calc accrued charges
        let charges = min(4, time_in_stake / stk_state.cooldown) as u8;
        charge_infos.push(ChargeInfo {
            token_id: id_img.id,
            charge_start: stk_inf.stake,
            charges,
        });
    }
    // retrieve the user's ingredient inventory
    let inventory = display_inventory(deps.storage, user_key)?;

    to_binary(&QueryAnswer::MyStaking {
        first_stake_bonus_available,
        charge_infos,
        inventory,
        staking_is_halted: stk_state.halt,
    })
}

/// Returns StdResult<Binary> displaying the list of ingredients
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
fn query_ingr(storage: &dyn Storage) -> StdResult<Binary> {
    let ingredients: Vec<String> = may_load(storage, INGREDIENTS_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::Ingredients { ingredients })
}

/// Returns StdResult<Binary> displaying the skull materials and their indices
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_mater(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let materials: Vec<String> = may_load(deps.storage, MATERIALS_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::Materials {
        materials: materials
            .into_iter()
            .enumerate()
            .map(|(i, m)| VariantIdxName {
                idx: i as u8,
                name: m,
            })
            .collect::<Vec<VariantIdxName>>(),
    })
}

/// Returns StdResult<Binary> displaying the staking and alchemy states
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_state(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let staking_state: StakingState = load(deps.storage, STAKING_STATE_KEY)?;
    let alchemy_state: AlchemyState = load(deps.storage, ALCHEMY_STATE_KEY)?;

    to_binary(&QueryAnswer::States {
        staking_state,
        alchemy_state,
    })
}

/// Returns StdResult<Binary> displaying the admin addresses
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_admins(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    let admins = check_admin_query(deps, viewer, permit, my_addr)?;
    to_binary(&QueryAnswer::Admins {
        admins: admins
            .iter()
            .map(|a| deps.api.addr_humanize(a))
            .collect::<StdResult<Vec<Addr>>>()?,
    })
}

/// Returns StdResult<(CanonicalAddr, String)> from determining the querying address
/// either from a Permit or a ViewerInfo
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn get_querier(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<(CanonicalAddr, String)> {
    if let Some(pmt) = permit {
        // Validate permit content
        let querier = validate(
            deps,
            PREFIX_REVOKED_PERMITS,
            &pmt,
            my_addr.to_string(),
            Some("secret"),
        )?;
        let raw = deps
            .api
            .addr_validate(&querier)
            .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
        if !pmt.check_permission(&secret_toolkit::permit::TokenPermissions::Owner) {
            return Err(StdError::generic_err(format!(
                "Owner permission is required for queries, got permissions {:?}",
                pmt.params.permissions
            )));
        }
        return Ok((raw, querier));
    }
    if let Some(vwr) = viewer {
        let hmn = deps.api.addr_validate(&vwr.address)?;
        let raw = deps.api.addr_canonicalize(hmn.as_str())?;
        ViewingKey::check(deps.storage, hmn.as_str(), &vwr.viewing_key).map_err(|_| {
            StdError::generic_err("Wrong viewing key for this address or viewing key not set")
        })?;
        return Ok((raw, vwr.address));
    }
    Err(StdError::generic_err(
        "A permit or viewing key must be provided",
    ))
}

/// Returns StdResult<Vec<CanonicalAddr>> which is the admin list and checks if the querier is an admin
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn check_admin_query(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Vec<CanonicalAddr>> {
    let (address, _) = get_querier(deps, viewer, permit, my_addr)?;
    check_admin(deps.storage, &address)
}

/// Returns StdResult<Vec<CanonicalAddr>> which is the admin list and checks if the message
/// sender is an admin
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
fn check_admin_tx(deps: Deps, sender: &Addr) -> StdResult<Vec<CanonicalAddr>> {
    let sender_raw = deps.api.addr_canonicalize(sender.as_str())?;
    check_admin(deps.storage, &sender_raw)
}

/// Returns StdResult<Vec<CanonicalAddr>> which is the admin list and checks if the address
/// is an admin
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `address` - a reference to the address in question
fn check_admin(storage: &dyn Storage, address: &CanonicalAddr) -> StdResult<Vec<CanonicalAddr>> {
    let admins: Vec<CanonicalAddr> = load(storage, ADMINS_KEY)?;
    if !admins.contains(address) {
        return Err(StdError::generic_err("Not an admin"));
    }
    Ok(admins)
}

/// Returns StdResult<Response>
///
/// updates the admin list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `update_list` - list of addresses to use for update
/// * `is_add` - true if the update is for adding to the list
fn try_process_auth_list(
    deps: DepsMut,
    sender: &Addr,
    update_list: &[String],
    is_add: bool,
) -> StdResult<Response> {
    // only allow admins to do this
    let mut admins = check_admin_tx(deps.as_ref(), sender)?;

    // update the authorization list if needed
    let save_it = if is_add {
        add_addrs_to_auth(deps.api, &mut admins, update_list)?
    } else {
        remove_addrs_from_auth(deps.api, &mut admins, update_list)?
    };
    // save list if it changed
    if save_it {
        save(deps.storage, ADMINS_KEY, &admins)?;
    }
    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::AdminsList {
            admins: admins
                .iter()
                .map(|a| deps.api.addr_humanize(a))
                .collect::<StdResult<Vec<Addr>>>()?,
        })?),
    )
}

/// Returns StdResult<bool>
///
/// adds to an authorization list of addresses and returns true if the list changed
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addresses` - current mutable list of addresses
/// * `addrs_to_add` - list of addresses to add
fn add_addrs_to_auth(
    api: &dyn Api,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_add: &[String],
) -> StdResult<bool> {
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = api
            .addr_validate(addr)
            .and_then(|a| api.addr_canonicalize(a.as_str()))?;
        if !addresses.contains(&raw) {
            addresses.push(raw);
            save_it = true;
        }
    }
    Ok(save_it)
}

/// Returns StdResult<bool>
///
/// removes from an authorization list of addresses and returns true if the list changed
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addresses` - current mutable list of addresses
/// * `addrs_to_remove` - list of addresses to remove
fn remove_addrs_from_auth(
    api: &dyn Api,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_remove: &[String],
) -> StdResult<bool> {
    let old_len = addresses.len();
    let rem_list = addrs_to_remove
        .iter()
        .map(|a| {
            api.addr_validate(a)
                .and_then(|a| api.addr_canonicalize(a.as_str()))
        })
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    addresses.retain(|a| !rem_list.contains(a));
    // only save if the list changed
    Ok(old_len != addresses.len())
}

// a skull's token id and the ImageInfo retrieved for it
pub struct IdImage {
    pub id: String,
    pub image: ImageInfo,
}

/// Returns StdResult<(Vec<IdImage>, Vec<String>)>
///
/// Verifies ownership of a list of skull token ids and returns the list of token ids and image infos for
/// skulls that have been verified to be owned by the specified address, and the list of token ids of the
/// skulls that do not belong to the address
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `owner` - a reference to the owner address for verification
/// * `skulls` - list of token ids to check
/// * `my_addr` - this contract's address
fn verify_ownership(
    deps: Deps,
    owner: &str,
    skulls: Vec<String>,
    my_addr: String,
) -> StdResult<(Vec<IdImage>, Vec<String>)> {
    let mut owned: Vec<IdImage> = Vec::new();
    let mut not_owned: Vec<String> = Vec::new();
    let viewing_key: String = load(deps.storage, MY_VIEWING_KEY)?;
    let viewer = ViewerInfo {
        address: my_addr,
        viewing_key,
    };
    let skull_contract = load::<StoreContractInfo>(deps.storage, SKULL_721_KEY)
        .and_then(|s| s.into_humanized(deps.api))?;

    for id in skulls.into_iter() {
        // see if this is a duplicate in the list
        if owned.iter().any(|i| i.id == id) {
            continue;
        }
        if not_owned.contains(&id) {
            continue;
        }
        // get the image info
        let img_inf_resp = Snip721QueryMsg::ImageInfo {
            token_id: id.clone(),
            viewer: viewer.clone(),
        }
        .query::<_, ImageInfoWrapper>(
            deps.querier,
            skull_contract.code_hash.clone(),
            skull_contract.address.clone(),
        )?
        .image_info;
        // if not the current owner
        if img_inf_resp.owner != *owner {
            not_owned.push(id);
        } else {
            owned.push(IdImage {
                id,
                image: img_inf_resp.image_info,
            });
        }
    }
    Ok((owned, not_owned))
}

/// Returns StdResult<Vec<u32>>
///
/// Take a list of charges per material type, and randomly draw resources according to the weighted staking table
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `env` - a reference to the Env of contract's environment
/// * `charges` - number of charges per material type
/// * `quantities` - number of skulls per material type
/// * `ingr_cnt` - number of different ingredients
fn gen_resources(
    storage: &dyn Storage,
    env: &Env,
    charges: &[u8],
    quantities: &[u8],
    ingr_cnt: usize,
) -> StdResult<Vec<u32>> {
    let mut generated: Vec<u32> = vec![0; ingr_cnt];
    let mut rng = ContractPrng::from_env(env);
    let type_cnt = quantities.iter().filter(|&q| *q > 0).count() as u8;
    let variety_lim = (2 * type_cnt) + 1;
    let mut ingr_sets: Vec<StoredIngrSet> = may_load(storage, INGRED_SETS_KEY)?.unwrap_or_default();
    let mut wins_per_set: Vec<u16> = vec![0; ingr_sets.len()];
    // go through each material type and the number of charges for each
    for (i, charge) in charges.iter().enumerate() {
        // process each charge for this material type
        for _ in 0u8..*charge {
            // randomly determine number of resources generated for this charge
            let mut draw_material: Vec<u8> = (0u8..(quantities[i] + 1)).collect();
            draw_material.shuffle(&mut rng.rng);
            let mut draw_variety: Vec<u8> = (0u8..variety_lim).collect();
            draw_variety.shuffle(&mut rng.rng);
            let rolls: u8 = 1 + draw_material[0] + draw_variety[0];
            let tbl_store = ReadonlyPrefixedStorage::new(storage, PREFIX_STAKING_TABLE);
            let i_sml = i as u8;
            let stk_tbl: Vec<StoredSetWeight> = load(&tbl_store, &i_sml.to_le_bytes())?;
            let just_weights: Vec<u16> = stk_tbl.iter().map(|t| t.weight).collect();
            let total_weight: u16 = just_weights.iter().sum();
            // randomly pick the winning ingredient set for each resource
            for _ in 0u8..rolls {
                let rdm = rng.next_u64();
                let winning_num: u16 = (rdm % total_weight as u64) as u16;
                let mut tally = 0u16;
                let mut winner = 0usize;
                for set_weight in stk_tbl.iter() {
                    // if the sum didn't panic on overflow, it can't happen here
                    tally += set_weight.weight;
                    if tally > winning_num {
                        winner = set_weight.set as usize;
                        break;
                    }
                }
                // increment wins for the winning ingredient set
                wins_per_set[winner] += 1;
            }
        }
    }
    // randomly pick ingredients from each winning set of ingredients
    for (idx, resource_cnt) in wins_per_set.iter().enumerate() {
        for _ in 0u16..*resource_cnt {
            ingr_sets[idx].list.shuffle(&mut rng.rng);
            generated[ingr_sets[idx].list[0] as usize] += 1;
        }
    }
    Ok(generated)
}

/// Returns StdResult<Vec<IngredientQty>>
///
/// generate resources for the charges and update user ingredients inventory
///
/// # Arguments
///
/// * `storage` - a mutable reference to this contract's storage
/// * `env` - a reference to the Env of contract's environment
/// * `charges` - number of charges per material type
/// * `quantities` - number of skulls per material type
/// * `user_key` - user address storage key
fn process_charges(
    storage: &mut dyn Storage,
    env: &Env,
    charges: &[u8],
    quantities: &[u8],
    user_key: &[u8],
) -> StdResult<Vec<IngredientQty>> {
    let mut rewards: Vec<IngredientQty> = Vec::new();
    let ingredients: Vec<String> = may_load(storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let ingr_cnt = ingredients.len();
    // generate the ingredients
    let generated = gen_resources(storage, env, charges, quantities, ingr_cnt)?;
    let mut inv_store = PrefixedStorage::new(storage, PREFIX_USER_INGR_INVENTORY);
    let mut inventory: Vec<u32> = may_load(&inv_store, user_key)?.unwrap_or_default();
    // just in case new ingredients get added, extend old inventories
    inventory.resize(ingr_cnt, 0);
    // add the newly generated resources
    for (inv, new) in inventory.iter_mut().zip(&generated) {
        *inv += *new;
    }
    save(&mut inv_store, user_key, &inventory)?;
    // create the list of generated resources for the output
    for (i, quantity) in generated.into_iter().enumerate() {
        if quantity > 0 {
            rewards.push(IngredientQty {
                ingredient: ingredients[i].clone(),
                quantity,
            });
        }
    }
    Ok(rewards)
}

/// Returns StdResult<Vec<IngredientQty>>
///
/// create a readable list of a user's ingredient inventory
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `user_key` - user address storage key
fn display_inventory(storage: &dyn Storage, user_key: &[u8]) -> StdResult<Vec<IngredientQty>> {
    let mut inventory: Vec<IngredientQty> = Vec::new();
    let ingredients: Vec<String> = may_load(storage, INGREDIENTS_KEY)?.unwrap_or_default();
    let ingr_cnt = ingredients.len();
    let inv_store = ReadonlyPrefixedStorage::new(storage, PREFIX_USER_INGR_INVENTORY);
    let mut raw_inv: Vec<u32> = may_load(&inv_store, user_key)?.unwrap_or_default();
    // just in case new ingredients get added, extend old inventories
    raw_inv.resize(ingr_cnt, 0);
    // create the readable list of ingredients
    for (i, quantity) in raw_inv.into_iter().enumerate() {
        inventory.push(IngredientQty {
            ingredient: ingredients[i].clone(),
            quantity,
        });
    }
    Ok(inventory)
}
