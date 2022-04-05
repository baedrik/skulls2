use cosmwasm_std::{
    log, to_binary, Api, CanonicalAddr, Env, Extern, HandleResponse, HandleResult, HumanAddr,
    InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage, StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    snip721::{
        batch_send_nft_msg, batch_transfer_nft_msg, register_receive_nft_msg, set_viewing_key_msg,
        Send, Transfer,
    },
    utils::{pad_handle_result, pad_query_result, HandleCallback},
};

use crate::contract_info::ContractInfo;
use crate::msg::{Claim, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg, ViewerInfo};
use crate::rand::{extend_entropy, sha_256, Prng};
use crate::snip721::{Mint, Snip721HandleMsg};
use crate::state::{
    ClaimInfo, Counts, RollConfig, StoredRedeem, ADMINS_KEY, CLAIM_KEY, MY_ADDRESS_KEY,
    PREFIX_COUNTS, PREFIX_DRAWN, PREFIX_REDEEM, PREFIX_REVOKED_PERMITS, PREFIX_VIEW_KEY,
    PREFIX_WINNER, PREFIX_WINNER_MAP, PRNG_SEED_KEY, ROLL_KEY,
};
use crate::storage::{load, may_load, remove, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the claim contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - InitMsg passed in with the instantiation message
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    save(
        &mut deps.storage,
        MY_ADDRESS_KEY,
        &deps.api.canonical_address(&env.contract.address)?,
    )?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy.as_bytes()).as_bytes()).to_vec();
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    let mut admins = vec![sender_raw];
    if let Some(addrs) = msg.admins {
        add_admins(&deps.api, &addrs, &mut admins)?;
    }
    save(&mut deps.storage, ADMINS_KEY, &admins)?;
    let claim = ClaimInfo {
        skulls: msg.skulls_contract.get_store(&deps.api)?,
        partner: msg.partner_info.contract.get_store(&deps.api)?,
        potion: msg.potion_contract.into_store(&deps.api)?,
        meta: msg.metadata,
    };
    save(&mut deps.storage, CLAIM_KEY, &claim)?;
    let roll = RollConfig {
        claimed: 0,
        partner: msg.partner_info.name,
        num_tokens: msg.partner_info.count,
        start_one: msg.partner_info.starts_at_one.unwrap_or(false),
        round: None,
        halted: false,
    };
    save(&mut deps.storage, ROLL_KEY, &roll)?;

    let messages = vec![
        // register with the skulls contract
        register_receive_nft_msg(
            env.contract_code_hash.clone(),
            Some(true),
            None,
            BLOCK_SIZE,
            msg.skulls_contract.code_hash,
            msg.skulls_contract.address,
        )?,
        // register with the partner contract
        register_receive_nft_msg(
            env.contract_code_hash,
            Some(true),
            None,
            BLOCK_SIZE,
            msg.partner_info.contract.code_hash,
            msg.partner_info.contract.address,
        )?,
    ];
    Ok(InitResponse {
        messages,
        log: vec![],
    })
}

///////////////////////////////////// Handle //////////////////////////////////////
/// Returns HandleResult
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - HandleMsg passed in with the execute message
pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    let response = match msg {
        HandleMsg::ReceiveNft { sender, token_id } => {
            try_batch_receive_nft(deps, &env.message.sender, sender, vec![token_id])
        }
        HandleMsg::BatchReceiveNft { from, token_ids } => {
            try_batch_receive_nft(deps, &env.message.sender, from, token_ids)
        }
        HandleMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, &env.message.sender, key),
        HandleMsg::AddAdmins { admins } => try_add_admins(deps, &env.message.sender, admins),
        HandleMsg::RemoveAdmins { admins } => try_remove_admins(deps, &env.message.sender, admins),
        HandleMsg::Raffle {
            num_picks,
            partner_percent,
            entropy,
        } => try_raffle(deps, &env, num_picks, partner_percent, &entropy),
        HandleMsg::RevokePermit { permit_name } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
        HandleMsg::SetViewingKeyWithCollection {
            nft_contract,
            viewing_key,
        } => try_set_key_with_coll(deps, &env.message.sender, nft_contract, viewing_key),
        HandleMsg::RetrieveNft {
            nft_contract,
            token_ids,
        } => try_retrieve(deps, env, nft_contract, token_ids),
        HandleMsg::SetHaltStatus { halt } => try_set_halt(deps, &env.message.sender, halt),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// sets halt status for claims
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `halt` - true if claims should be halted
fn try_set_halt<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    halt: bool,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut roll: RollConfig = load(&deps.storage, ROLL_KEY)?;
    if roll.halted != halt {
        roll.halted = halt;
        save(&mut deps.storage, ROLL_KEY, &roll)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetHaltStatus {
            halted: roll.halted,
        })?),
    })
}

/// Returns HandleResult
///
/// handles receiving NFTs to process claims
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender's address
/// * `from` - the address that owned the NFT used to claim
/// * `token_ids` - list of tokens sent for claiming
fn try_batch_receive_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    from: HumanAddr,
    token_ids: Vec<String>,
) -> HandleResult {
    let collection_raw = deps.api.canonical_address(sender)?;
    let claim_inf: ClaimInfo = load(&deps.storage, CLAIM_KEY)?;
    let mut roll: RollConfig = load(&deps.storage, ROLL_KEY)?;
    if roll.halted {
        return Err(StdError::generic_err("Claims have been halted"));
    }
    let round = roll
        .round
        .as_ref()
        .copied()
        .ok_or_else(|| StdError::generic_err("No winners have been drawn yet"))?;
    let round_key = round.to_le_bytes();
    let count_store = ReadonlyPrefixedStorage::new(PREFIX_COUNTS, &deps.storage);
    let mut counts: Counts = may_load(&count_store, &round_key)?
        .ok_or_else(|| StdError::generic_err("Counts storage is corrupt"))?;
    // get info for the collection being used to claim
    let (coll_info, unclaimed, is_skull) = if collection_raw == claim_inf.skulls.address {
        // claiming with skulls
        (claim_inf.skulls, &mut counts.skulls, true)
    } else if collection_raw == claim_inf.partner.address {
        // claiming with the partner NFTs
        (claim_inf.partner, &mut counts.partner, false)
    } else {
        return Err(StdError::generic_err("This can only be called by either the mystic skulls token contract or the partner collection contract"));
    };
    let mut redeemed: Vec<String> = Vec::new();
    let mut mints: Vec<Mint> = Vec::new();
    let (coll_key, coll_name) = if is_skull {
        (0u8.to_le_bytes(), "Mystic Skulls".to_string())
    } else {
        (1u8.to_le_bytes(), roll.partner.clone())
    };
    for id in token_ids.iter() {
        let id_key = id.as_bytes();
        // if this token is eligible for a claim in this round
        let mut map_store = PrefixedStorage::multilevel(
            &[PREFIX_WINNER_MAP, &coll_key, &round_key],
            &mut deps.storage,
        );
        if let Some(idx) = may_load::<u32, _>(&map_store, id_key)? {
            redeemed.push(id.clone());
            // don't let it get claimed again
            remove(&mut map_store, id_key);
            // remove the token id from the list of unredeemed NFTs
            // count can not be 0 if the NFT was found in the map store
            let last_idx = *unclaimed - 1;
            let last_idx_key = last_idx.to_le_bytes();
            // if this is not the last winner, need to swap the last winner to this index
            if idx != last_idx {
                // swap the last token id to the claimed index
                let mut win_store = PrefixedStorage::multilevel(
                    &[PREFIX_WINNER, &coll_key, &round_key],
                    &mut deps.storage,
                );
                let last_wnr: String = may_load(&win_store, &last_idx_key)?
                    .ok_or_else(|| StdError::generic_err("Winner storage is corrupt"))?;
                save(&mut win_store, &idx.to_le_bytes(), &last_wnr)?;
                // save its new index to the map
                let mut map_store = PrefixedStorage::multilevel(
                    &[PREFIX_WINNER_MAP, &coll_key, &round_key],
                    &mut deps.storage,
                );
                save(&mut map_store, last_wnr.as_bytes(), &idx)?
            }
            let mut win_store = PrefixedStorage::multilevel(
                &[PREFIX_WINNER, &coll_key, &round_key],
                &mut deps.storage,
            );
            remove(&mut win_store, &last_idx_key);
            // add the NFT to the list of redeemed NFTs
            let redeem = StoredRedeem {
                is_skull,
                token_id: id.clone(),
                owner: deps.api.canonical_address(&from)?,
                round,
            };
            let mut redeem_store = PrefixedStorage::new(PREFIX_REDEEM, &mut deps.storage);
            save(&mut redeem_store, &roll.claimed.to_le_bytes(), &redeem)?;
            // define the mint
            mints.push(Mint {
                owner: from.clone(),
                public_metadata: claim_inf.meta.clone(),
                memo: format!("Claimed with {} {}", &coll_name, &id),
            });
            // change claimed and unclaimed counts
            roll.claimed += 1;
            *unclaimed = unclaimed.saturating_sub(1);
        }
    }
    // return the NFTs
    let coll = coll_info.into_humanized(&deps.api)?;
    let sends = vec![Send {
        contract: from,
        token_ids,
        msg: None,
        memo: Some(format!("Returning {} sent to claim potions", coll_name)),
    }];
    let mut messages = vec![batch_send_nft_msg(
        sends,
        None,
        BLOCK_SIZE,
        coll.code_hash,
        coll.address,
    )?];
    // if potions were claimed
    if !mints.is_empty() {
        save(&mut deps.storage, ROLL_KEY, &roll)?;
        let mut count_store = PrefixedStorage::new(PREFIX_COUNTS, &mut deps.storage);
        save(&mut count_store, &round_key, &counts)?;
        let mint_msg = Snip721HandleMsg::BatchMintNft { mints };
        let potion = claim_inf.potion.into_humanized(&deps.api)?;
        messages.push(mint_msg.to_cosmos_msg(potion.code_hash, potion.address, None)?);
    }

    Ok(HandleResponse {
        messages,
        log: vec![log("redeemed", format!("{:?}", &redeemed))],
        data: None,
    })
}

/// Returns HandleResult
///
/// sets a viewing key with a contract.  This is only used to facilitate in the retrieval of an nft
/// accidentally sent from an unregistered collection
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `nft_contract` - code hash and address of the unregistered collection
/// * `viewing_key` - viewing key to set with the unregistered collection
fn try_set_key_with_coll<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    nft_contract: ContractInfo,
    viewing_key: String,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let messages = vec![set_viewing_key_msg(
        viewing_key.clone(),
        None,
        BLOCK_SIZE,
        nft_contract.code_hash,
        nft_contract.address,
    )?];
    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey { key: viewing_key })?),
    })
}

/// Returns HandleResult
///
/// retrieves nfts sent from an unregistered collection
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - the Env of contract's environment
/// * `nft_contract` - code hash and address of the unregistered collection
/// * `token_ids` - list of nfts to retrieve
fn try_retrieve<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    nft_contract: ContractInfo,
    token_ids: Vec<String>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let transfers = vec![Transfer {
        recipient: env.message.sender,
        token_ids,
        memo: Some(format!(
            "Retrieved from mystic skulls claim contract: {}",
            env.contract.address
        )),
    }];
    let messages = vec![batch_transfer_nft_msg(
        transfers,
        None,
        BLOCK_SIZE,
        nft_contract.code_hash,
        nft_contract.address,
    )?];
    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RetrieveNft {
            status: "success".to_string(),
        })?),
    })
}

/// Returns HandleResult
///
/// selects NFTS that can be used to claim potions
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `num_picks` - the number of NFTs to draw
/// * `partner_percent` - the percentage drawn that should go to owners of the partner NFTs
/// * `entropy` - entropy string slice for the prng
fn try_raffle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    num_picks: u32,
    partner_percent: u8,
    entropy: &str,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut config: RollConfig = load(&deps.storage, ROLL_KEY)?;
    // increment the round
    let round = config.round.map_or(0, |r| r + 1);
    config.round = Some(round);
    save(&mut deps.storage, ROLL_KEY, &config)?;
    let round_key = round.to_le_bytes();
    if partner_percent > 100 {
        return Err(StdError::generic_err(
            "The percentage of picks given to the partner collection can not be more than 100",
        ));
    }
    let ptnr_cnt = (num_picks as u64 * partner_percent as u64 / 100) as u32;
    let skull_cnt = num_picks - ptnr_cnt;
    // init the prng
    let mut prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let rng_entropy = extend_entropy(
        env.block.height,
        env.block.time,
        &env.message.sender,
        entropy.as_bytes(),
    );
    let mut prng = Prng::new(&prng_seed, &rng_entropy);
    // draw the skulls
    roll(
        &mut deps.storage,
        &mut prng,
        skull_cnt,
        10000u32,
        &round_key,
        0u32,
        &0u8.to_le_bytes(),
    )?;
    // draw the partner
    let modifier = if config.start_one { 1u32 } else { 0u32 };
    roll(
        &mut deps.storage,
        &mut prng,
        ptnr_cnt,
        config.num_tokens,
        &round_key,
        modifier,
        &1u8.to_le_bytes(),
    )?;
    // update the seed
    prng_seed = prng.rand_bytes().to_vec();
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    // save the draw counts for the round
    let counts = Counts {
        skulls: skull_cnt,
        partner: ptnr_cnt,
    };
    let mut count_store = PrefixedStorage::new(PREFIX_COUNTS, &mut deps.storage);
    save(&mut count_store, &round_key, &counts)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Raffle {
            skulls: counts.skulls,
            partner: counts.partner,
        })?),
    })
}

/// Returns HandleResult
///
/// remove a list of admins from the list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `admins_to_remove` - list of admin addresses to remove
fn try_remove_admins<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    admins_to_remove: Vec<HumanAddr>,
) -> HandleResult {
    // only allow admins to do this
    let mut admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let old_len = admins.len();
    let rem_list = admins_to_remove
        .iter()
        .map(|a| deps.api.canonical_address(a))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    admins.retain(|a| !rem_list.contains(a));
    // only save if the list changed
    if old_len != admins.len() {
        save(&mut deps.storage, ADMINS_KEY, &admins)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AdminsList {
            admins: admins
                .iter()
                .map(|a| deps.api.human_address(a))
                .collect::<StdResult<Vec<HumanAddr>>>()?,
        })?),
    })
}

/// Returns HandleResult
///
/// adds a list of admins to the list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `admins_to_add` - list of admin addresses to add
fn try_add_admins<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    admins_to_add: Vec<HumanAddr>,
) -> HandleResult {
    // only allow admins to do this
    let mut admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    // only save if the list changed
    if add_admins(&deps.api, &admins_to_add, &mut admins)? {
        save(&mut deps.storage, ADMINS_KEY, &admins)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AdminsList {
            admins: admins
                .iter()
                .map(|a| deps.api.human_address(a))
                .collect::<StdResult<Vec<HumanAddr>>>()?,
        })?),
    })
}

/// Returns HandleResult
///
/// creates a viewing key
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `entropy` - string slice of the input String to be used as entropy in randomization
fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    entropy: &str,
) -> HandleResult {
    let prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let key = ViewingKey::new(env, &prng_seed, entropy.as_ref());
    let message_sender = &deps.api.canonical_address(&env.message.sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &key.to_hashed())?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey { key: key.0 })?),
    })
}

/// Returns HandleResult
///
/// sets the viewing key to the input String
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `key` - String to be used as the viewing key
fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    key: String,
) -> HandleResult {
    let vk = ViewingKey(key.clone());
    let message_sender = &deps.api.canonical_address(sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &vk.to_hashed())?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey { key })?),
    })
}

/// Returns HandleResult
///
/// revoke the ability to use a specified permit
///
/// # Arguments
///
/// * `storage` - mutable reference to the contract's storage
/// * `sender` - a reference to the message sender
/// * `permit_name` - string slice of the name of the permit to revoke
fn revoke_permit<S: Storage>(
    storage: &mut S,
    sender: &HumanAddr,
    permit_name: &str,
) -> HandleResult {
    RevokedPermits::revoke_permit(storage, PREFIX_REVOKED_PERMITS, sender, permit_name);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RevokePermit {
            status: "success".to_string(),
        })?),
    })
}

/////////////////////////////////////// Query /////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::SkullsRedeemable {
            round,
            page,
            page_size,
        } => query_redeemable(&deps.storage, true, round, page, page_size),
        QueryMsg::PartnerRedeemable {
            round,
            page,
            page_size,
        } => query_redeemable(&deps.storage, false, round, page, page_size),
        QueryMsg::Admins { viewer, permit } => query_admins(deps, viewer, permit),
        QueryMsg::Claimed {
            viewer,
            permit,
            page,
            page_size,
        } => query_claimed(deps, viewer, permit, page, page_size),
        QueryMsg::WhichAreWinners { skulls, partner } => {
            query_which(&deps.storage, skulls, partner)
        }
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying which of the supplied token IDs are eligible to claim
/// potions
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
/// * `skulls` - list of skulls to check
/// * `partner` - list of partner NFTs to check
fn query_which<S: ReadonlyStorage>(
    storage: &S,
    skulls: Vec<String>,
    partner: Vec<String>,
) -> QueryResult {
    let roll: RollConfig = load(storage, ROLL_KEY)?;
    let round = roll
        .round
        .ok_or_else(|| StdError::generic_err("No winners have been drawn yet"))?;
    let round_key = round.to_le_bytes();
    let joined = vec![skulls, partner];
    let mut winners: Vec<Vec<String>> = vec![Vec::new(), Vec::new()];
    for (coll, ids) in joined.into_iter().enumerate() {
        let map_store = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_WINNER_MAP, &(coll as u8).to_le_bytes(), &round_key],
            storage,
        );
        let wnrs = winners.get_mut(coll).ok_or_else(|| {
            StdError::generic_err("Impossible for winners Vec to have less than 2 elements")
        })?;
        for id in ids.into_iter() {
            if may_load::<u32, _>(&map_store, id.as_bytes())?.is_some() {
                wnrs.push(id);
            }
        }
    }
    let partner = winners
        .pop()
        .ok_or_else(|| StdError::generic_err("We know the winners Vec has 2 elements"))?;
    let skulls = winners
        .pop()
        .ok_or_else(|| StdError::generic_err("We know the winners Vec has 2 elements"))?;
    to_binary(&QueryAnswer::WhichAreWinners {
        halted: roll.halted,
        skulls,
        partner,
    })
}

/// Returns QueryResult displaying the potion claims made
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page
/// * `page_size` - optional max number of claims to return
fn query_claimed<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u32>,
    page_size: Option<u32>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let roll: RollConfig = load(&deps.storage, ROLL_KEY)?;
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(30);
    let start = page * limit;
    let end = min(start + limit, roll.claimed);
    let redeem_store = ReadonlyPrefixedStorage::new(PREFIX_REDEEM, &deps.storage);
    let mut claims: Vec<Claim> = Vec::new();
    for idx in start..end {
        if let Some(rdm) = may_load::<StoredRedeem, _>(&redeem_store, &idx.to_le_bytes())? {
            claims.push(rdm.into_human(&deps.api, &roll.partner)?);
        }
    }
    to_binary(&QueryAnswer::Claimed {
        count: roll.claimed,
        claims,
    })
}

/// Returns QueryResult displaying the admin list
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_admins<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (admins, _) = check_admin(deps, viewer, permit)?;
    to_binary(&QueryAnswer::Admins {
        admins: admins
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
    })
}

/// Returns QueryResult displaying NFTs eligible to be redeemed for one collection/round
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
/// * `is_skulls` - true if querying redeemable skulls
/// * `round` - optional drawing round
/// * `page` - optional page
/// * `page_size` - optional max number of token IDs to return
fn query_redeemable<S: ReadonlyStorage>(
    storage: &S,
    is_skulls: bool,
    round: Option<u16>,
    page: Option<u32>,
    page_size: Option<u32>,
) -> QueryResult {
    let roll: RollConfig = load(storage, ROLL_KEY)?;
    let cur_round = roll
        .round
        .ok_or_else(|| StdError::generic_err("No winners have been drawn yet"))?;
    let qry_round = round.unwrap_or(cur_round);
    let round_key = qry_round.to_le_bytes();
    let count_store = ReadonlyPrefixedStorage::new(PREFIX_COUNTS, storage);
    let counts: Counts = may_load(&count_store, &round_key)?
        .ok_or_else(|| StdError::generic_err("Counts storage is corrupt"))?;
    let (collection_key, collection, count) = if is_skulls {
        (
            0u8.to_le_bytes(),
            "Mystic Skulls".to_string(),
            counts.skulls,
        )
    } else {
        (1u8.to_le_bytes(), roll.partner, counts.partner)
    };
    let win_store =
        ReadonlyPrefixedStorage::multilevel(&[PREFIX_WINNER, &collection_key, &round_key], storage);
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(100);
    let start = page * limit;
    let end = min(start + limit, count);
    let mut token_ids: Vec<String> = Vec::new();
    for idx in start..end {
        if let Some(winner) = may_load::<String, _>(&win_store, &idx.to_le_bytes())? {
            token_ids.push(winner);
        }
    }
    to_binary(&QueryAnswer::Redeemable {
        halted: roll.halted,
        round: qry_round,
        collection,
        count,
        token_ids,
    })
}

/// Returns StdResult<(CanonicalAddr, Option<CanonicalAddr>)> from determining the querying address
/// (if possible) either from a Permit or a ViewerInfo.  Also returns this server's address if
/// a permit was supplied
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn get_querier<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> StdResult<(CanonicalAddr, Option<CanonicalAddr>)> {
    if let Some(pmt) = permit {
        // Validate permit content
        let me_raw: CanonicalAddr = may_load(&deps.storage, MY_ADDRESS_KEY)?
            .ok_or_else(|| StdError::generic_err("Minter contract address storage is corrupt"))?;
        let my_address = deps.api.human_address(&me_raw)?;
        let querier = deps.api.canonical_address(&validate(
            deps,
            PREFIX_REVOKED_PERMITS,
            &pmt,
            my_address,
        )?)?;
        if !pmt.check_permission(&secret_toolkit::permit::Permission::Owner) {
            return Err(StdError::generic_err(format!(
                "Owner permission is required for queries, got permissions {:?}",
                pmt.params.permissions
            )));
        }
        return Ok((querier, Some(me_raw)));
    }
    if let Some(vwr) = viewer {
        let raw = deps.api.canonical_address(&vwr.address)?;
        // load the address' key
        let key_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, &deps.storage);
        let load_key: [u8; VIEWING_KEY_SIZE] =
            may_load(&key_store, raw.as_slice())?.unwrap_or_else(|| [0u8; VIEWING_KEY_SIZE]);
        let input_key = ViewingKey(vwr.viewing_key);
        // if key matches
        if input_key.check_viewing_key(&load_key) {
            return Ok((raw, None));
        }
    }
    Err(StdError::unauthorized())
}

/// Returns StdResult<(Vec<CanonicalAddr>, Option<CanonicalAddr>)> which is the the list of admins and this
/// contract's address if it has been retrieved, and checks if the querier is an admin
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn check_admin<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> StdResult<(Vec<CanonicalAddr>, Option<CanonicalAddr>)> {
    let (querier, my_addr) = get_querier(deps, viewer, permit)?;
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    if !admins.contains(&querier) {
        return Err(StdError::unauthorized());
    }
    Ok((admins, my_addr))
}

/// Returns StdResult<bool> which is true if the admin list has changed after attempting
/// to add a list of addresses that do not collide
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `addrs_to_add` - list of addresses to add
/// * `admins` - a mutable reference to the list of admins
fn add_admins<A: Api>(
    api: &A,
    addrs_to_add: &[HumanAddr],
    admins: &mut Vec<CanonicalAddr>,
) -> StdResult<bool> {
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = api.canonical_address(addr)?;
        if !admins.contains(&raw) {
            admins.push(raw);
            save_it = true;
        }
    }
    Ok(save_it)
}

/// Returns StdResult<()> after randomly selecting token ids that can be used to claim potions
///
/// # Arguments
///
/// * `storage` - a mutable reference to the contract's storage
/// * `prng` - a mutable reference to the Prng
/// * `draws` - the number of tokens to draw
/// * `tokens` - number of tokens in the collection
/// * `round_key` - drawing round as bytes
/// * `modifier` - 1u32 if the token IDs start with "1", 0u32 if starts with "0"
/// * `collection_key` - [0u8] if drawing skulls, [1u8] if drawing partner
fn roll<S: Storage>(
    storage: &mut S,
    prng: &mut Prng,
    draws: u32,
    tokens: u32,
    round_key: &[u8],
    modifier: u32,
    collection_key: &[u8],
) -> StdResult<()> {
    let mut drew = 0u32;
    while drew < draws {
        // select a winner
        let winner = (prng.next_u64() % tokens as u64) as u32 + modifier;
        let winner_str = format!("{}", winner);
        let winner_key = winner_str.as_bytes();
        let mut drawn_store = PrefixedStorage::multilevel(&[PREFIX_DRAWN, collection_key], storage);
        // don't allow redraws of the same NFT
        if may_load::<bool, _>(&drawn_store, winner_key)?.is_none() {
            save(&mut drawn_store, winner_key, &true)?;
            let mut map_store = PrefixedStorage::multilevel(
                &[PREFIX_WINNER_MAP, collection_key, round_key],
                storage,
            );
            save(&mut map_store, winner_key, &drew)?;
            let mut win_store =
                PrefixedStorage::multilevel(&[PREFIX_WINNER, collection_key, round_key], storage);
            save(&mut win_store, &drew.to_le_bytes(), &winner_str)?;
            drew += 1;
        }
    }
    Ok(())
}
