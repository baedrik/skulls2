use cosmwasm_std::{
    from_binary, log, to_binary, Api, Binary, CanonicalAddr, CosmosMsg, Env, Extern,
    HandleResponse, HandleResult, HumanAddr, InitResponse, InitResult, Querier, QueryResult,
    StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    snip721::{
        batch_transfer_nft_msg, burn_nft_msg, register_receive_nft_msg, set_viewing_key_msg,
        Transfer,
    },
    utils::{pad_handle_result, pad_query_result, HandleCallback, Query},
};

use crate::contract_info::ContractInfo;
use crate::msg::{
    HandleAnswer, HandleMsg, InitMsg, PotionInfo, PotionNameIdx, QueryAnswer, QueryMsg, ViewerInfo,
};
use crate::rand::{extend_entropy, sha_256, Prng};
use crate::server_msgs::{ServerQueryMsg, SkullTypeWrapper, TransmuteWrapper};
use crate::snip721::{
    ImageInfoWrapper, NftInfoResponse, SendMsg, Snip721HandleMsg, Snip721QueryMsg,
};
use crate::state::{
    State, StoredPotionInfo, ADMINS_KEY, MY_ADDRESS_KEY, PREFIX_POTION, PREFIX_POTION_IDX,
    PREFIX_REVOKED_PERMITS, PREFIX_VIEW_KEY, PRNG_SEED_KEY, STATE_KEY,
};
use crate::storage::{load, may_load, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the alchemy contract
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
    let vk = ViewingKey::new(&env, &prng_seed, msg.entropy.as_ref());
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    let mut admins = vec![sender_raw];
    if let Some(addrs) = msg.admins {
        add_admins(&deps.api, &addrs, &mut admins)?;
    }
    save(&mut deps.storage, ADMINS_KEY, &admins)?;
    let mut state = State {
        skulls: msg.skulls_contract.get_store(&deps.api)?,
        potion_contracts: Vec::new(),
        svg_contracts: Vec::new(),
        potion_cnt: 0,
        v_key: vk.0,
        halt: false,
    };
    // add a potion if given
    let mut messages = if let Some(ptn) = msg.potion {
        set_potion(deps, ptn, &mut state, &env.contract_code_hash)?
    } else {
        Vec::new()
    };
    // register receive with any potion contracts povided
    if let Some(ptns) = msg.potion_contracts {
        let mut add_msgs = add_ptn_contrs(deps, &mut state, ptns, &env.contract_code_hash)?;
        messages.append(&mut add_msgs);
    }
    // set viewing keys with any svg servers provided
    if let Some(svgs) = msg.svg_servers {
        let mut add_msgs = add_svg_contrs(deps, &mut state, svgs)?;
        messages.append(&mut add_msgs);
    }
    save(&mut deps.storage, STATE_KEY, &state)?;
    // set vk with skulls
    messages.push(set_viewing_key_msg(
        state.v_key,
        None,
        BLOCK_SIZE,
        msg.skulls_contract.code_hash,
        msg.skulls_contract.address,
    )?);

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
        HandleMsg::SetPotion { potion } => try_set_potion(deps, &env, potion),
        HandleMsg::AddContracts {
            potion_contracts,
            svg_servers,
        } => try_add_contracts(deps, &env, potion_contracts, svg_servers),
        HandleMsg::RemovePotionContracts { potion_contracts } => {
            try_remove_ptn_contrs(deps, &env.message.sender, potion_contracts)
        }
        HandleMsg::ReceiveNft {
            sender,
            token_id,
            msg,
        } => try_batch_receive_nft(deps, env, sender, vec![token_id], msg),
        HandleMsg::BatchReceiveNft {
            from,
            token_ids,
            msg,
        } => try_batch_receive_nft(deps, env, from, token_ids, msg),
        HandleMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, &env.message.sender, key),
        HandleMsg::AddAdmins { admins } => try_add_admins(deps, &env.message.sender, admins),
        HandleMsg::RemoveAdmins { admins } => try_remove_admins(deps, &env.message.sender, admins),
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
        HandleMsg::SetHaltStatus { potion, halt } => {
            try_set_halt(deps, &env.message.sender, potion, halt)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// sets halt status for the contract
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `potion` - optional name of the only potion whose status should be updated
/// * `halt` - true if all alchemy should be halted
fn try_set_halt<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    potion: Option<String>,
    halt: bool,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    // if only setting status for one potion
    if let Some(name) = potion.as_ref() {
        let idx_store = ReadonlyPrefixedStorage::new(PREFIX_POTION_IDX, &deps.storage);
        let i = may_load::<u16, _>(&idx_store, name.as_bytes())?
            .ok_or_else(|| StdError::generic_err(format!("No potion called {}", name)))?;
        let idx_key = i.to_le_bytes();
        let mut ptn_store = PrefixedStorage::new(PREFIX_POTION, &mut deps.storage);
        let mut potion = may_load::<StoredPotionInfo, _>(&ptn_store, &idx_key)?
            .ok_or_else(|| StdError::generic_err("Potion storage is corrupt"))?;
        if potion.halt != halt {
            potion.halt = halt;
            save(&mut ptn_store, &idx_key, &potion)?;
        }
    // setting status for the contract
    } else {
        let mut state: State = load(&deps.storage, STATE_KEY)?;
        if state.halt != halt {
            state.halt = halt;
            save(&mut deps.storage, STATE_KEY, &state)?;
        }
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetHaltStatus {
            potion,
            halted: halt,
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
/// * `env` - the Env of contract's environment
/// * `from` - the address that owned the NFT used to claim
/// * `token_ids` - list of tokens sent for claiming
/// * `msg` - the msg stating which skull to apply the potion to
fn try_batch_receive_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    mut token_ids: Vec<String>,
    msg: Option<Binary>,
) -> HandleResult {
    let mut state: State = load(&deps.storage, STATE_KEY)?;
    if state.halt {
        return Err(StdError::generic_err("Alchemy has been halted"));
    }
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let ptn_contract = if let Some(pos) = state
        .potion_contracts
        .iter()
        .position(|p| p.address == sender_raw)
    {
        state
            .potion_contracts
            .swap_remove(pos)
            .into_humanized(&deps.api)?
    } else {
        return Err(StdError::generic_err(
            "This can only be called by an official Mystic Skulls potion contract",
        ));
    };
    if token_ids.len() != 1 {
        return Err(StdError::generic_err(
            "Alchemy will only process one potion at a time",
        ));
    }
    let ptn_qry_msg = Snip721QueryMsg::NftInfo {
        token_id: token_ids[0].clone(),
    };
    let ptn_meta = ptn_qry_msg
        .query::<_, NftInfoResponse>(
            &deps.querier,
            ptn_contract.code_hash.clone(),
            ptn_contract.address.clone(),
        )?
        .nft_info;
    let idx_store = ReadonlyPrefixedStorage::new(PREFIX_POTION_IDX, &deps.storage);
    let ptn_idx =
        may_load::<u16, _>(&idx_store, ptn_meta.extension.name.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!("Unknown potion: {}", ptn_meta.extension.name))
        })?;
    let ptn_store = ReadonlyPrefixedStorage::new(PREFIX_POTION, &deps.storage);
    let mut potion = may_load::<StoredPotionInfo, _>(&ptn_store, &ptn_idx.to_le_bytes())?
        .ok_or_else(|| StdError::generic_err("Potion storage is corrupt"))?;
    if potion.halt {
        return Err(StdError::generic_err(format!(
            "Alchemy for potion: {} has been halted",
            potion.name
        )));
    }
    let svg = state
        .svg_contracts
        .swap_remove(potion.svg_server as usize)
        .into_humanized(&deps.api)?;
    let skulls = state.skulls.into_humanized(&deps.api)?;
    let send_msg: SendMsg = from_binary(
        &msg.ok_or_else(|| StdError::generic_err("Skull ID and entropy not provided"))?,
    )
    .map_err(|_e| StdError::generic_err("Invalid msg supplied with BatchSendNft"))?;
    // init the viewer info
    let viewer = ViewerInfo {
        address: env.contract.address.clone(),
        viewing_key: state.v_key,
    };
    // get the skull's image info
    let img_msg = Snip721QueryMsg::ImageInfo {
        token_id: send_msg.skull.clone(),
        viewer: viewer.clone(),
    };
    let mut image_resp = img_msg
        .query::<_, ImageInfoWrapper>(
            &deps.querier,
            skulls.code_hash.clone(),
            skulls.address.clone(),
        )?
        .image_info;
    // potions can only be applied to skulls you own
    if from != image_resp.owner {
        return Err(StdError::unauthorized());
    }
    // can only apply potions to completely revealed skulls
    if image_resp.image_info.current.iter().any(|u| *u == 255) {
        return Err(StdError::generic_err(
            "Potions can only be applied to completely revealed skulls",
        ));
    }
    // set the skull's svg server if this potion uses a different one
    if image_resp.server_used.address != svg.address {
        image_resp.image_info.svg_server = Some(svg.address.clone());
    }
    // create the prng
    let mut prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let rng_entropy = extend_entropy(
        env.block.height,
        env.block.time,
        &from,
        send_msg.entropy.as_bytes(),
    );
    let mut rng = Prng::new(&prng_seed, &rng_entropy);
    // find out if the skull is cyclops/jawless
    let type_msg = ServerQueryMsg::SkullType {
        viewer: viewer.clone(),
        image: image_resp.image_info.current.clone(),
    };
    let type_resp = type_msg
        .query::<_, SkullTypeWrapper>(
            &deps.querier,
            image_resp.server_used.code_hash,
            image_resp.server_used.address,
        )?
        .skull_type;
    let mut total_weight = 0u16;
    let mut weights = Vec::new();
    for var in potion.variants.iter() {
        let wgt = if let Some(cy) = var.cyclops_weight {
            if type_resp.is_cyclops {
                cy
            } else {
                var.normal_weight
            }
        } else if let Some(jl) = var.jawless_weight {
            if type_resp.is_jawless {
                jl
            } else {
                var.normal_weight
            }
        } else {
            var.normal_weight
        };
        total_weight += wgt;
        weights.push(wgt);
    }
    let rdm = rng.next_u64();
    let winning_num: u16 = (rdm % total_weight as u64) as u16;
    let mut tally = 0u16;
    let mut winner = 0usize;
    for (idx, weight) in weights.iter().enumerate() {
        // if the sum didn't panic on overflow, it can't happen here
        tally += weight;
        if tally > winning_num {
            winner = idx;
            break;
        }
    }
    // update the seed
    prng_seed = rng.rand_bytes().to_vec();
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    let new_layers = potion.variants.swap_remove(winner).layers;
    let cat_trans: Vec<String> = new_layers.iter().map(|l| l.category.clone()).collect();
    let xmut_msg = ServerQueryMsg::Transmute {
        viewer,
        current: image_resp.image_info.current.clone(),
        new_layers,
    };
    let current = xmut_msg
        .query::<_, TransmuteWrapper>(&deps.querier, svg.code_hash, svg.address)?
        .transmute
        .image;
    // update new image and previous state
    image_resp.image_info.previous = image_resp.image_info.current;
    image_resp.image_info.current = current;
    let memo = Some(format!("Applied to Mystic Skull #{}", &send_msg.skull));
    let set_img_msg = Snip721HandleMsg::SetImageInfo {
        token_id: send_msg.skull,
        image_info: image_resp.image_info,
    };
    let mut messages: Vec<CosmosMsg> =
        vec![set_img_msg.to_cosmos_msg(skulls.code_hash, skulls.address, None)?];
    let token_id = token_ids.pop().ok_or_else(|| {
        StdError::generic_err("Already checked the token_id length so this is not possible")
    })?;
    messages.push(burn_nft_msg(
        token_id,
        memo,
        None,
        BLOCK_SIZE,
        ptn_contract.code_hash,
        ptn_contract.address,
    )?);

    Ok(HandleResponse {
        messages,
        log: vec![log("transmuted categories", format!("{:?}", &cat_trans))],
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
/// adds potions and svg server contracts and creates the appropriate messages to register receive and
/// set viewing keys
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `potion_contracts` - list of potion contracts to add
/// * `svg_servers` - list of svg server contracts to add
fn try_add_contracts<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    potion_contracts: Option<Vec<ContractInfo>>,
    svg_servers: Option<Vec<ContractInfo>>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut state: State = load(&deps.storage, STATE_KEY)?;
    let mut messages = if let Some(ptns) = potion_contracts {
        add_ptn_contrs(deps, &mut state, ptns, &env.contract_code_hash)?
    } else {
        Vec::new()
    };
    if let Some(svgs) = svg_servers {
        let mut add_msgs = add_svg_contrs(deps, &mut state, svgs)?;
        messages.append(&mut add_msgs);
    }
    save(&mut deps.storage, STATE_KEY, &state)?;

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddContracts {
            potion_contracts: state
                .potion_contracts
                .into_iter()
                .map(|c| c.into_humanized(&deps.api))
                .collect::<StdResult<Vec<ContractInfo>>>()?,
            svg_servers: state
                .svg_contracts
                .into_iter()
                .map(|c| c.into_humanized(&deps.api))
                .collect::<StdResult<Vec<ContractInfo>>>()?,
        })?),
    })
}

/// Returns HandleResult
///
/// remove a list of potion contracts
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `contracts_to_remove` - list of potion contracts to remove
fn try_remove_ptn_contrs<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    contracts_to_remove: Vec<HumanAddr>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut state: State = load(&deps.storage, STATE_KEY)?;
    let old_len = state.potion_contracts.len();
    let rem_list = contracts_to_remove
        .iter()
        .map(|a| deps.api.canonical_address(a))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    state
        .potion_contracts
        .retain(|p| !rem_list.contains(&p.address));
    // only save if the list changed
    if old_len != state.potion_contracts.len() {
        save(&mut deps.storage, STATE_KEY, &state)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RemovePotionContracts {
            potion_contracts: state
                .potion_contracts
                .into_iter()
                .map(|p| p.into_humanized(&deps.api))
                .collect::<StdResult<Vec<ContractInfo>>>()?,
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
/// adds/updates a potion's info
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of contract's environment
/// * `potion` - the new/updated PotionInfo
fn try_set_potion<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    potion: PotionInfo,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut state: State = load(&deps.storage, STATE_KEY)?;
    let old_cnt = state.potion_cnt;
    let messages = set_potion(deps, potion, &mut state, &env.contract_code_hash)?;
    save(&mut deps.storage, STATE_KEY, &state)?;

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetPotion {
            count: state.potion_cnt,
            updated_existing: state.potion_cnt == old_cnt,
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
        QueryMsg::Admins { viewer, permit } => query_admins(deps, viewer, permit),
        QueryMsg::PotionContracts { viewer, permit } => query_contracts(deps, viewer, permit, true),
        QueryMsg::SvgServers { viewer, permit } => query_contracts(deps, viewer, permit, false),
        QueryMsg::Potions {
            viewer,
            permit,
            page,
            page_size,
        } => query_name_idx(deps, viewer, permit, page, page_size),
        QueryMsg::PotionInfo {
            viewer,
            permit,
            name,
            index,
        } => query_potion(deps, viewer, permit, name, index),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying either potion or svg server contracts
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `is_potion` - true if querying potion contracts
fn query_contracts<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    is_potion: bool,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let state: State = load(&deps.storage, STATE_KEY)?;
    let raws = if is_potion {
        state.potion_contracts
    } else {
        state.svg_contracts
    };
    let hmns = raws
        .into_iter()
        .map(|c| c.into_humanized(&deps.api))
        .collect::<StdResult<Vec<ContractInfo>>>()?;
    let resp = if is_potion {
        QueryAnswer::PotionContracts {
            potion_contracts: hmns,
        }
    } else {
        QueryAnswer::SvgServers { svg_servers: hmns }
    };
    to_binary(&resp)
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

/// Returns QueryResult displaying an optionally paginated list of potion names and indices
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `page` - optional page
/// * `page_size` - optional max number of potions to return
fn query_name_idx<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    page: Option<u16>,
    page_size: Option<u16>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let state: State = load(&deps.storage, STATE_KEY)?;
    let page = page.unwrap_or(0);
    let limit = page_size.unwrap_or(100);
    let start = page * limit;
    let end = min(start + limit, state.potion_cnt);
    let ptn_store = ReadonlyPrefixedStorage::new(PREFIX_POTION, &deps.storage);
    let mut potions: Vec<PotionNameIdx> = Vec::new();
    for idx in start..end {
        if let Some(potion) = may_load::<StoredPotionInfo, _>(&ptn_store, &idx.to_le_bytes())? {
            potions.push(PotionNameIdx {
                name: potion.name,
                index: idx as u16,
            });
        }
    }

    to_binary(&QueryAnswer::Potions {
        count: state.potion_cnt,
        potions,
    })
}

/// Returns QueryResult displaying the definition of a specified potion
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `name` - optional potion name
/// * `index` - optional potion index
fn query_potion<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    name: Option<String>,
    index: Option<u16>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let idx = if let Some(i) = index {
        i
    } else if let Some(nm) = name {
        let idx_store = ReadonlyPrefixedStorage::new(PREFIX_POTION_IDX, &deps.storage);
        may_load::<u16, _>(&idx_store, nm.as_bytes())?
            .ok_or_else(|| StdError::generic_err(format!("No potion with name: {}", nm)))?
    } else {
        return Err(StdError::generic_err(
            "The potion name or index must be provided",
        ));
    };
    let ptn_store = ReadonlyPrefixedStorage::new(PREFIX_POTION, &deps.storage);
    let stored: StoredPotionInfo = may_load(&ptn_store, &idx.to_le_bytes())?
        .ok_or_else(|| StdError::generic_err("Potion storage is corrupt"))?;
    let mut state: State = load(&deps.storage, STATE_KEY)?;
    let potion = PotionInfo {
        name: stored.name,
        potion_contract: None,
        svg_server: state
            .svg_contracts
            .swap_remove(stored.svg_server as usize)
            .into_humanized(&deps.api)?,
        variants: stored.variants,
    };

    to_binary(&QueryAnswer::PotionInfo {
        halted: stored.halt,
        potion,
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

/// Returns StdResult<Vec<CosmosMsg>> after adding/modifying potion data
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `potion` - PotionInfo to add
/// * `state` - a mutable reference to the contract State
/// * `code_hash` - this contract's code hash
fn set_potion<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    potion: PotionInfo,
    state: &mut State,
    code_hash: &str,
) -> StdResult<Vec<CosmosMsg>> {
    let name_key = potion.name.as_bytes();
    let mut idx_store = PrefixedStorage::new(PREFIX_POTION_IDX, &mut deps.storage);
    let idx = if let Some(i) = may_load::<u16, _>(&idx_store, name_key)? {
        i
    } else {
        let i = state.potion_cnt;
        save(&mut idx_store, name_key, &i)?;
        state.potion_cnt = state.potion_cnt.checked_add(1).ok_or_else(|| {
            StdError::generic_err("Reached the implementation limit for the number of potions")
        })?;
        i
    };
    let idx_key = idx.to_le_bytes();
    // store the potion contract if needed
    let mut msgs = if let Some(contract) = potion.potion_contract {
        add_ptn_contrs(deps, state, vec![contract], code_hash)?
    } else {
        Vec::new()
    };
    let raw = potion.svg_server.get_store(&deps.api)?;
    // only add the svg server if it is not already there
    let svg_server = if let Some(pos) = state
        .svg_contracts
        .iter()
        .position(|s| s.address == raw.address)
    {
        pos as u8
    } else {
        state.svg_contracts.push(raw);
        // set a viewing key with the new svg server
        msgs.push(set_viewing_key_msg(
            state.v_key.clone(),
            None,
            BLOCK_SIZE,
            potion.svg_server.code_hash,
            potion.svg_server.address,
        )?);
        (state.svg_contracts.len() - 1) as u8
    };
    let store_ptn = StoredPotionInfo {
        name: potion.name,
        svg_server,
        variants: potion.variants,
        halt: false,
    };
    let mut ptn_store = PrefixedStorage::new(PREFIX_POTION, &mut deps.storage);
    save(&mut ptn_store, &idx_key, &store_ptn)?;
    Ok(msgs)
}

/// Returns StdResult<Vec<CosmosMsg>> after adding potion contracts and registering with them
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `state` - a mutable reference to the contract State
/// * `potion_contrs` - list of potion contracts to add
/// * `code_hash` - this contract's code hash
fn add_ptn_contrs<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    state: &mut State,
    potion_contrs: Vec<ContractInfo>,
    code_hash: &str,
) -> StdResult<Vec<CosmosMsg>> {
    let mut messages: Vec<CosmosMsg> = Vec::new();
    for contract in potion_contrs.into_iter() {
        let raw = contract.get_store(&deps.api)?;
        // only add the potion if it is not already there
        if !state
            .potion_contracts
            .iter()
            .any(|p| p.address == raw.address)
        {
            state.potion_contracts.push(raw);
            // register with the potion contract
            messages.push(register_receive_nft_msg(
                code_hash.to_string(),
                Some(true),
                None,
                BLOCK_SIZE,
                contract.code_hash,
                contract.address,
            )?);
        }
    }
    Ok(messages)
}

/// Returns StdResult<Vec<CosmosMsg>> after adding svg server contracts and setting viewing keys
/// with them
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `state` - a mutable reference to the contract State
/// * `svg_contrs` - list of svg server contracts to add
fn add_svg_contrs<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    state: &mut State,
    svg_contrs: Vec<ContractInfo>,
) -> StdResult<Vec<CosmosMsg>> {
    let mut messages: Vec<CosmosMsg> = Vec::new();
    for contract in svg_contrs.into_iter() {
        let raw = contract.get_store(&deps.api)?;
        // only add the server if it is not already there
        if !state.svg_contracts.iter().any(|s| s.address == raw.address) {
            state.svg_contracts.push(raw);
            // register with the potion contract
            messages.push(set_viewing_key_msg(
                state.v_key.clone(),
                None,
                BLOCK_SIZE,
                contract.code_hash,
                contract.address,
            )?);
        }
    }
    Ok(messages)
}
