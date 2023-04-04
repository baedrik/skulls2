use cosmwasm_std::{
    to_binary, Api, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse, HandleResult, HumanAddr,
    InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage, StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    snip20::set_viewing_key_msg,
    utils::{pad_handle_result, pad_query_result, HandleCallback, Query},
};

use crate::contract_info::ContractInfo;
use crate::msg::{HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg, TokenTime};
use crate::rand::sha_256;
use crate::server_msgs::{ServeAlchemyWrapper, ServerQueryMsg};
use crate::snip721::{
    ImageInfoWrapper, IsOwnerWrapper, QueryWithPermit, Snip721HandleMsg, Snip721QueryMsg,
    ViewerInfo,
};
use crate::state::{
    Config, CONFIG_KEY, MY_ADDRESS_KEY, PREFIX_REVOKED_PERMITS, PREFIX_TIMESTAMP, PREFIX_VIEW_KEY,
    PRNG_SEED_KEY,
};
use crate::storage::{load, may_load, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the rewind contract
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
    let vk = ViewingKey::new(&env, &prng_seed, msg.entropy.as_ref());
    let admins = vec![sender_raw];
    let config = Config {
        nft_contract: msg.nft_contract.get_store(&deps.api)?,
        halt: false,
        admins,
        viewing_key: vk.0,
        cooldown: msg.cooldown,
    };
    save(&mut deps.storage, CONFIG_KEY, &config)?;

    Ok(InitResponse {
        messages: vec![
            set_viewing_key_msg(
                config.viewing_key.clone(),
                None,
                BLOCK_SIZE,
                msg.nft_contract.code_hash,
                msg.nft_contract.address,
            )?,
            set_viewing_key_msg(
                config.viewing_key,
                None,
                BLOCK_SIZE,
                msg.svg_server.code_hash,
                msg.svg_server.address,
            )?,
        ],
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
        HandleMsg::CreateViewingKey { entropy } => try_create_key(deps, &env, &entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, &env.message.sender, key),
        HandleMsg::AddAdmins { admins } => try_add_admins(deps, &env.message.sender, &admins),
        HandleMsg::RemoveAdmins { admins } => try_remove_admins(deps, &env.message.sender, &admins),
        HandleMsg::RevokePermit { permit_name } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
        HandleMsg::SetRewindStatus { halt } => try_set_status(deps, &env.message.sender, halt),
        HandleMsg::SetCooldown { cooldown } => {
            try_set_cooldown(deps, &env.message.sender, cooldown)
        }
        HandleMsg::SetKeyWithServer { svg_server } => {
            try_set_key_w_server(deps, &env.message.sender, svg_server)
        }
        HandleMsg::Rewind { token_id } => try_rewind(deps, env, token_id),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// rewinds token trait(s)
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `token_id` - ID of token being rewound
fn try_rewind<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    token_id: String,
) -> HandleResult {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    if config.halt {
        return Err(StdError::generic_err("Rewinds have been halted"));
    }
    let me_raw: CanonicalAddr = may_load(&deps.storage, MY_ADDRESS_KEY)?
        .ok_or_else(|| StdError::generic_err("Rewind contract address storage is corrupt"))?;
    let address = deps.api.human_address(&me_raw)?;
    let viewer = ViewerInfo {
        address,
        viewing_key: config.viewing_key,
    };
    // get the token's image info
    let img_msg = Snip721QueryMsg::ImageInfo {
        token_id: token_id.clone(),
        viewer: viewer.clone(),
    };
    let collection = config.nft_contract.into_humanized(&deps.api)?;
    let img_wrap: ImageInfoWrapper = img_msg.query(
        &deps.querier,
        collection.code_hash.clone(),
        collection.address.clone(),
    )?;
    let mut image = img_wrap.image_info;
    // only let the token's owner rewind
    if env.message.sender != image.owner {
        return Err(StdError::unauthorized());
    }
    // check the time of last rewind
    let mut time_store = PrefixedStorage::new(PREFIX_TIMESTAMP, &mut deps.storage);
    let token_key = token_id.as_bytes();
    if let Some(last) = may_load::<u64, _>(&time_store, token_key)? {
        let next_rewind = last + config.cooldown;
        if next_rewind > env.block.time {
            return Err(StdError::generic_err(format!(
                "This skull can not be rewound until {}",
                next_rewind
            )));
        }
    }
    // only let fully revealed skulls be rewound
    if image.image_info.current.iter().any(|u| *u == 255) {
        return Err(StdError::generic_err(
            "Only fully revealed skulls may be rewound",
        ));
    }
    // can not rewind to an unrevealed state
    if image.image_info.previous.iter().any(|u| *u == 255) {
        return Err(StdError::generic_err(
            "Can not rewind if the previous state was not fully revealed",
        ));
    }
    // no rewind possible
    if image.image_info.previous == image.image_info.current {
        return Err(StdError::generic_err(
            "This skull has not been altered from its last save point",
        ));
    }
    save(&mut time_store, token_key, &env.block.time)?;
    // get the svg server info
    let svr_msg = ServerQueryMsg::ServeAlchemy { viewer };
    let svr_wrap: ServeAlchemyWrapper = svr_msg.query(
        &deps.querier,
        image.server_used.code_hash,
        image.server_used.address,
    )?;
    // get the names of rewound categories
    let cur = &image.image_info.current;
    let prev = &image.image_info.previous;
    let categories_rewound = svr_wrap
        .serve_alchemy
        .category_names
        .into_iter()
        .enumerate()
        .filter_map(|(i, c)| if cur[i] != prev[i] { Some(c) } else { None })
        .collect();
    image.image_info.current = image.image_info.previous.clone();

    let set_img_msg = Snip721HandleMsg::SetImageInfo {
        token_id,
        image_info: image.image_info,
    };
    let messages: Vec<CosmosMsg> =
        vec![set_img_msg.to_cosmos_msg(collection.code_hash, collection.address, None)?];

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Rewind { categories_rewound })?),
    })
}

/// Returns HandleResult
///
/// updates the rewind status
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `halt` - true if minting should halt
fn try_set_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    halt: bool,
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    // only save it if the status is different
    if config.halt != halt {
        config.halt = halt;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetRewindStatus {
            rewind_has_halted: halt,
        })?),
    })
}

/// Returns HandleResult
///
/// sets a viewing key with the svg server
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `svg_server` - ContractInfo of the svg server to set a key with
fn try_set_key_w_server<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    svg_server: ContractInfo,
) -> HandleResult {
    // only allow admins to do this
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }

    Ok(HandleResponse {
        messages: vec![set_viewing_key_msg(
            config.viewing_key,
            None,
            BLOCK_SIZE,
            svg_server.code_hash,
            svg_server.address,
        )?],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetKeyWithServer {
            status: "success".to_string(),
        })?),
    })
}

/// Returns HandleResult
///
/// updates the cooldown period
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `cooldown` - new rewind cooldown period in seconds
fn try_set_cooldown<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    cooldown: u64,
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    if config.cooldown != cooldown {
        config.cooldown = cooldown;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetCooldown {
            cooldown: config.cooldown,
        })?),
    })
}

/// Returns HandleResult
///
/// adds to the the admin list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `addrs_to_add` - list of addresses to add
fn try_add_admins<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    addrs_to_add: &[HumanAddr],
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = deps.api.canonical_address(addr)?;
        if !config.admins.contains(&raw) {
            config.admins.push(raw);
            save_it = true;
        }
    }
    // save list if it changed
    if save_it {
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    let admins = config
        .admins
        .iter()
        .map(|a| deps.api.human_address(a))
        .collect::<StdResult<Vec<HumanAddr>>>()?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AdminsList { admins })?),
    })
}

/// Returns HandleResult
///
/// removes from the admin list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `addrs_to_remove` - list of addresses to remove
fn try_remove_admins<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    addrs_to_remove: &[HumanAddr],
) -> HandleResult {
    // only allow admins to do this
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !config.admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let old_len = config.admins.len();
    let rem_list = addrs_to_remove
        .iter()
        .map(|a| deps.api.canonical_address(a))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    config.admins.retain(|a| !rem_list.contains(a));
    // only save if the list changed
    if old_len != config.admins.len() {
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    let admins = config
        .admins
        .iter()
        .map(|a| deps.api.human_address(a))
        .collect::<StdResult<Vec<HumanAddr>>>()?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AdminsList { admins })?),
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
        QueryMsg::RewindStatus {} => query_status(&deps.storage),
        QueryMsg::Cooldown {} => query_cooldowns(&deps.storage),
        QueryMsg::Admins { viewer, permit } => query_admins(deps, viewer, permit),
        QueryMsg::NftContract {} => query_nft_contract(deps),
        QueryMsg::LastRewindTimes {
            token_ids,
            viewer,
            permit,
        } => query_rewind_times(deps, token_ids, viewer, permit),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying the last rewind times for a list of tokens
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `token_ids` - list of tokens
/// * `viewer_opt` - optional address and key making an authenticated query request
/// * `permit_opt` - optional permit with "owner" permission
fn query_rewind_times<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_ids: Vec<String>,
    viewer_opt: Option<ViewerInfo>,
    permit_opt: Option<Permit>,
) -> QueryResult {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    // verify ownership
    let own_msg = if let Some(permit) = permit_opt {
        Snip721QueryMsg::WithPermit {
            permit,
            query: QueryWithPermit::IsOwner {
                token_ids: token_ids.clone(),
            },
        }
    } else if let Some(viewer) = viewer_opt {
        Snip721QueryMsg::IsOwner {
            token_ids: token_ids.clone(),
            viewer,
        }
    } else {
        return Err(StdError::generic_err(
            "A viewer or permit must be provided for this query",
        ));
    };
    let collection = config.nft_contract.into_humanized(&deps.api)?;
    let own_wrap: IsOwnerWrapper =
        own_msg.query(&deps.querier, collection.code_hash, collection.address)?;
    if !own_wrap.is_owner.is_owner {
        return Err(StdError::unauthorized());
    }
    let time_store = ReadonlyPrefixedStorage::new(PREFIX_TIMESTAMP, &deps.storage);
    to_binary(&QueryAnswer::LastRewindTimes {
        last_rewinds: token_ids
            .into_iter()
            .map(|i| {
                Ok(TokenTime {
                    timestamp: may_load(&time_store, i.as_bytes())?,
                    token_id: i,
                })
            })
            .collect::<StdResult<Vec<TokenTime>>>()?,
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
    let (config, _) = check_admin(deps, viewer, permit)?;
    to_binary(&QueryAnswer::Admins {
        admins: config
            .admins
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
    })
}

/// Returns QueryResult displaying the nft contract information
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
fn query_nft_contract<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::NftContract {
        nft_contract: config.nft_contract.into_humanized(&deps.api)?,
    })
}

/// Returns QueryResult displaying the rewind status
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
fn query_status<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::RewindStatus {
        rewind_has_halted: config.halt,
    })
}

/// Returns QueryResult displaying the cooldown period
///
/// # Arguments
///
/// * `storage` - reference to the contract's storage
fn query_cooldowns<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::Cooldown {
        cooldown: config.cooldown,
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
            .ok_or_else(|| StdError::generic_err("Rewind contract address storage is corrupt"))?;
        let my_address = deps.api.human_address(&me_raw)?;
        let querier = deps.api.canonical_address(&HumanAddr(validate(
            deps,
            PREFIX_REVOKED_PERMITS,
            &pmt,
            my_address,
            Some("secret"),
        )?))?;
        if !pmt.check_permission(&secret_toolkit::permit::TokenPermissions::Owner) {
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
            may_load(&key_store, raw.as_slice())?.unwrap_or([0u8; VIEWING_KEY_SIZE]);
        let input_key = ViewingKey(vwr.viewing_key);
        // if key matches
        if input_key.check_viewing_key(&load_key) {
            return Ok((raw, None));
        }
    }
    Err(StdError::unauthorized())
}

/// Returns StdResult<(Config, Option<CanonicalAddr>)> which is the Config and this
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
) -> StdResult<(Config, Option<CanonicalAddr>)> {
    let (admin, my_addr) = get_querier(deps, viewer, permit)?;
    // only allow admins to do this
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    if !config.admins.contains(&admin) {
        return Err(StdError::unauthorized());
    }
    Ok((config, my_addr))
}
