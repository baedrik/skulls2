use cosmwasm_std::{
    to_binary, Api, CanonicalAddr, Env, Extern, HandleResponse, HandleResult, HumanAddr,
    InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage, StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    permit::{validate, Permit, RevokedPermits},
    utils::{pad_handle_result, pad_query_result},
};

use crate::metadata::{Metadata, Trait};
use crate::msg::{
    AddVariantInfo, CategoryInfo, CommonMetadata, Dependencies, HandleAnswer, HandleMsg, InitMsg,
    LayerId, QueryAnswer, QueryMsg, StoredDependencies, StoredLayerId, VariantInfo,
    VariantInfoPlus, VariantModInfo, ViewerInfo,
};
use crate::rand::sha_256;
use crate::state::{
    Category, State, ADMINS_KEY, DEPENDENCIES_KEY, METADATA_KEY, MINTERS_KEY, MY_ADDRESS_KEY,
    PREFIX_CATEGORY, PREFIX_CATEGORY_MAP, PREFIX_REVOKED_PERMITS, PREFIX_VARIANT,
    PREFIX_VARIANT_MAP, PREFIX_VIEW_KEY, PRNG_SEED_KEY, STATE_KEY, VIEWERS_KEY,
};
use crate::storage::{load, may_load, remove, save};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the server contract
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
        add_addrs_to_auth(&deps.api, &mut admins, &addrs)?;
    }
    save(&mut deps.storage, ADMINS_KEY, &admins)?;
    let state = State {
        cat_cnt: 0u8,
        skip: Vec::new(),
    };
    save(&mut deps.storage, STATE_KEY, &state)?;

    Ok(InitResponse::default())
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
        HandleMsg::AddCategories { categories } => {
            try_add_categories(deps, &env.message.sender, categories)
        }
        HandleMsg::AddVariants { variants } => {
            try_add_variants(deps, &env.message.sender, variants)
        }
        HandleMsg::ModifyCategory {
            name,
            new_name,
            new_skip,
        } => try_modify_category(deps, &env.message.sender, &name, new_name, new_skip),
        HandleMsg::ModifyVariants { modifications } => {
            try_modify_variants(deps, &env.message.sender, modifications)
        }
        HandleMsg::SetMetadata {
            public_metadata,
            private_metadata,
        } => try_set_metadata(deps, &env.message.sender, public_metadata, private_metadata),
        HandleMsg::AddAdmins { admins } => {
            try_process_auth_list(deps, &env.message.sender, &admins, true, AddrType::Admin)
        }
        HandleMsg::RemoveAdmins { admins } => {
            try_process_auth_list(deps, &env.message.sender, &admins, false, AddrType::Admin)
        }
        HandleMsg::AddViewers { viewers } => {
            try_process_auth_list(deps, &env.message.sender, &viewers, true, AddrType::Viewer)
        }
        HandleMsg::RemoveViewers { viewers } => {
            try_process_auth_list(deps, &env.message.sender, &viewers, false, AddrType::Viewer)
        }
        HandleMsg::AddMinters { minters } => {
            try_process_auth_list(deps, &env.message.sender, &minters, true, AddrType::Minter)
        }
        HandleMsg::RemoveMinters { minters } => {
            try_process_auth_list(deps, &env.message.sender, &minters, false, AddrType::Minter)
        }
        HandleMsg::AddDependencies { dependencies } => {
            try_process_dep_list(deps, &env.message.sender, &dependencies, Action::Add)
        }
        HandleMsg::RemoveDependencies { dependencies } => {
            try_process_dep_list(deps, &env.message.sender, &dependencies, Action::Remove)
        }
        HandleMsg::ModifyDependencies { dependencies } => {
            try_process_dep_list(deps, &env.message.sender, &dependencies, Action::Modify)
        }
        HandleMsg::RevokePermit { permit_name } => {
            revoke_permit(&mut deps.storage, &env.message.sender, &permit_name)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// sets the common metadata for all NFTs
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `public_metadata` - optional public metadata used for all NFTs
/// * `private_metadata` - optional private metadata used for all NFTs
fn try_set_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut common: CommonMetadata =
        may_load(&deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
            public: None,
            private: None,
        });

    let mut save_common = false;
    // update public metadata
    if let Some(pub_meta) = public_metadata {
        let new_pub = filter_metadata(pub_meta)?;
        if common.public != new_pub {
            common.public = new_pub;
            save_common = true;
        }
    }
    // update private metadata
    if let Some(priv_meta) = private_metadata {
        let new_priv = filter_metadata(priv_meta)?;
        if common.private != new_priv {
            common.private = new_priv;
            save_common = true;
        }
    }
    if save_common {
        // if both metadata are None, just remove it
        if common.public.is_none() && common.private.is_none() {
            remove(&mut deps.storage, METADATA_KEY);
        } else {
            save(&mut deps.storage, METADATA_KEY, &common)?;
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMetadata { metadata: common })?),
    })
}

/// Returns HandleResult
///
/// changes the name and skip status of a category
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `name` - name of the category to change
/// * `new_name` - optional new name for the category
/// * `new_skip` - optional new skip status for this category
fn try_modify_category<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    name: &str,
    new_name: Option<String>,
    new_skip: Option<bool>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let cat_name_key = name.as_bytes();
    let mut cat_map = PrefixedStorage::new(PREFIX_CATEGORY_MAP, &mut deps.storage);
    if let Some(cat_idx) = may_load::<u8, _>(&cat_map, cat_name_key)? {
        let mut save_cat = false;
        let cat_key = cat_idx.to_le_bytes();
        let mut may_cat: Option<Category> = None;
        if let Some(new_nm) = new_name {
            if new_nm != name {
                // remove the mapping for the old name
                remove(&mut cat_map, cat_name_key);
                // map the category idx to the new name
                save(&mut cat_map, new_nm.as_bytes(), &cat_idx)?;
                let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
                let mut cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| {
                    StdError::generic_err(format!("Category storage for {} is corrupt", name))
                })?;
                cat.name = new_nm;
                may_cat = Some(cat);
                save_cat = true;
            }
        }
        if let Some(skip) = new_skip {
            let mut cat = may_cat.map_or_else(
                || {
                    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
                    may_load::<Category, _>(&cat_store, &cat_key)?.ok_or_else(|| {
                        StdError::generic_err(format!("Category storage for {} is corrupt", name))
                    })
                },
                Ok,
            )?;
            if cat.skip != skip {
                let mut state: State = load(&deps.storage, STATE_KEY)?;
                let mut save_skip = false;
                if skip {
                    if !state.skip.contains(&cat_idx) {
                        state.skip.push(cat_idx);
                        save_skip = true;
                    }
                } else if let Some(pos) = state.skip.iter().position(|s| *s == cat_idx) {
                    state.skip.swap_remove(pos);
                    save_skip = true;
                }
                if save_skip {
                    save(&mut deps.storage, STATE_KEY, &state)?;
                }
                cat.skip = skip;
                save_cat = true;
            }
            may_cat = Some(cat);
        }
        if save_cat {
            let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
            save(
                &mut cat_store,
                &cat_key,
                &may_cat.ok_or_else(|| {
                    StdError::generic_err("May_cat can not be None if save_cat is true")
                })?,
            )?;
        }
    } else {
        return Err(StdError::generic_err(format!(
            "Category name:  {} does not exist",
            name
        )));
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ModifyCategory {
            status: "success".to_string(),
        })?),
    })
}

/// Returns HandleResult
///
/// adds new trait categories
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `categories` - the new trait categories
fn try_add_categories<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    categories: Vec<CategoryInfo>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut state: State = load(&deps.storage, STATE_KEY)?;
    for cat_inf in categories.into_iter() {
        let cat_name_key = cat_inf.name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        if may_load::<u8, _>(&cat_map, cat_name_key)?.is_some() {
            return Err(StdError::generic_err(format!(
                "Category name:  {} already exists",
                cat_inf.name
            )));
        }
        // add the entry to the category map for this category name
        let mut cat_map = PrefixedStorage::new(PREFIX_CATEGORY_MAP, &mut deps.storage);
        save(&mut cat_map, cat_name_key, &state.cat_cnt)?;
        let cat_key = state.cat_cnt.to_le_bytes();
        let mut cat = Category {
            name: cat_inf.name,
            skip: cat_inf.skip,
            cnt: 0,
        };
        add_variants(&mut deps.storage, &cat_key, cat_inf.variants, &mut cat)?;
        let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
        save(&mut cat_store, &cat_key, &cat)?;
        state.cat_cnt = state
            .cat_cnt
            .checked_add(1)
            .ok_or_else(|| StdError::generic_err("Reached maximum number of trait categories"))?;
    }
    save(&mut deps.storage, STATE_KEY, &state)?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddCategories {
            count: state.cat_cnt,
        })?),
    })
}

/// Returns HandleResult
///
/// modifies existing trait variants
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `modifications` - the updated trait variants and the categories they belong to
fn try_modify_variants<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    modifications: Vec<VariantModInfo>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    for cat_inf in modifications.into_iter() {
        let cat_name = cat_inf.category;
        let cat_name_key = cat_name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        // if valid category name
        if let Some(cat_idx) = may_load::<u8, _>(&cat_map, cat_name_key)? {
            let cat_key = cat_idx.to_le_bytes();
            for var_mod in cat_inf.modifications.into_iter() {
                let var_name_key = var_mod.name.as_bytes();
                let mut var_map =
                    PrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, &cat_key], &mut deps.storage);
                let var_idx: u8 = may_load(&var_map, var_name_key)?.ok_or_else(|| {
                    StdError::generic_err(format!(
                        "Category {} does not have a variant named {}",
                        &cat_name, var_mod.name
                    ))
                })?;
                // if changing the variant name
                if var_mod.name != var_mod.modified_variant.name {
                    // remove the old name from the map and add the new one
                    remove(&mut var_map, var_name_key);
                    save(
                        &mut var_map,
                        var_mod.modified_variant.name.as_bytes(),
                        &var_idx,
                    )?;
                }
                let mut var_store =
                    PrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], &mut deps.storage);
                save(
                    &mut var_store,
                    &var_idx.to_le_bytes(),
                    &var_mod.modified_variant,
                )?;
            }
        } else {
            return Err(StdError::generic_err(format!(
                "Category name:  {} does not exist",
                &cat_name
            )));
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ModifyVariants {
            status: "success".to_string(),
        })?),
    })
}

/// Returns HandleResult
///
/// adds new trait variants to existing categories
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `variants` - the new trait variants and the categories they belong to
fn try_add_variants<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    variants: Vec<AddVariantInfo>,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    for cat_inf in variants.into_iter() {
        let cat_name_key = cat_inf.category_name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        if let Some(cat_idx) = may_load::<u8, _>(&cat_map, cat_name_key)? {
            let cat_key = cat_idx.to_le_bytes();
            let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
            let mut cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| {
                StdError::generic_err(format!(
                    "Category storage for {} is corrupt",
                    cat_inf.category_name
                ))
            })?;
            add_variants(&mut deps.storage, &cat_key, cat_inf.variants, &mut cat)?;
            let mut cat_store = PrefixedStorage::new(PREFIX_CATEGORY, &mut deps.storage);
            save(&mut cat_store, &cat_key, &cat)?;
        } else {
            return Err(StdError::generic_err(format!(
                "Category name:  {} does not exist",
                cat_inf.category_name
            )));
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddVariants {
            status: "success".to_string(),
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
        QueryMsg::AuthorizedAddresses { viewer, permit } => query_addresses(deps, viewer, permit),
        QueryMsg::Category {
            viewer,
            permit,
            name,
            index,
            start_at,
            limit,
            display_svg,
        } => query_category(
            deps,
            viewer,
            permit,
            name.as_deref(),
            index,
            start_at,
            limit,
            display_svg,
        ),
        QueryMsg::Variant {
            viewer,
            permit,
            by_name,
            by_index,
            display_svg,
        } => query_variant(
            deps,
            viewer,
            permit,
            by_name.as_ref(),
            by_index,
            display_svg,
        ),
        QueryMsg::CommonMetadata { viewer, permit } => query_common_metadata(deps, viewer, permit),
        QueryMsg::State { viewer, permit } => query_state(deps, viewer, permit),
        QueryMsg::Dependencies {
            viewer,
            permit,
            start_at,
            limit,
        } => query_dependencies(deps, viewer, permit, start_at, limit),
        QueryMsg::TokenMetadata {
            viewer,
            permit,
            image,
        } => query_token_metadata(deps, viewer, permit, &image),
        QueryMsg::ServeAlchemy { viewer } => query_serve_alchemy(deps, viewer),
        QueryMsg::SkullType { viewer, image } => query_skull_type(deps, viewer, &image),
        QueryMsg::Transmute {
            viewer,
            current,
            new_layers,
        } => query_transmute(deps, viewer, current, &new_layers),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult which displays the new image vec after transmuting as requested
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
/// * `current` - the current image indices
/// * `new_layers` - the new image layers to incorporate
fn query_transmute<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: ViewerInfo,
    mut current: Vec<u8>,
    new_layers: &[LayerId],
) -> QueryResult {
    let (querier, _) = get_querier(deps, Some(viewer), None)?;
    // only allow viewers to call this
    let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    if !viewers.contains(&querier) {
        return Err(StdError::unauthorized());
    }
    // can only transmute fully revealed skulls
    if current.iter().any(|u| *u == 255) {
        return Err(StdError::generic_err(
            "Only fully revealed skulls may be transmuted",
        ));
    }
    // change to the transmuted background if it isn't already
    if current[0] < 6 {
        let back_idx_key = 0u8.to_le_bytes();
        let back_var_store =
            ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &back_idx_key], &deps.storage);
        let var: VariantInfo = may_load(&back_var_store, &current[0].to_le_bytes())?
            .ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
        let new_back = format!("Background.{}.Transmuted", &var.display_name);
        let back_var_map = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_VARIANT_MAP, &back_idx_key],
            &deps.storage,
        );
        current[0] = may_load(&back_var_map, new_back.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!("Did not find Background variant {}", &new_back))
        })?;
    }
    let dependencies: Vec<StoredDependencies> =
        may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let state: State = load(&deps.storage, STATE_KEY)?;
    let mut cat_cache: Vec<BackCache> = Vec::new();
    let mut var_caches: Vec<Vec<BackCache>> = vec![Vec::new(); state.cat_cnt as usize];
    // update each requested layer
    for layer in new_layers.iter() {
        replace_layer(
            &deps.storage,
            &mut current,
            layer,
            &dependencies,
            &mut cat_cache,
            &mut var_caches,
        )?;
    }

    to_binary(&QueryAnswer::Transmute { image: current })
}

/// Returns QueryResult which displays if a skull is a cyclops and if it is jawless
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
/// * `image` - the image indices
fn query_skull_type<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: ViewerInfo,
    image: &[u8],
) -> QueryResult {
    let (querier, _) = get_querier(deps, Some(viewer), None)?;
    // only allow viewers to call this
    let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    if !viewers.contains(&querier) {
        return Err(StdError::unauthorized());
    }
    let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
    let eye_type_idx: u8 = may_load(&cat_map, "Eye Type".as_bytes())?
        .ok_or_else(|| StdError::generic_err("Eye Type layer category not found"))?;
    let chin_idx: u8 = may_load(&cat_map, "Jaw Type".as_bytes())?
        .ok_or_else(|| StdError::generic_err("Jaw Type layer category not found"))?;
    let chin_var_map = ReadonlyPrefixedStorage::multilevel(
        &[PREFIX_VARIANT_MAP, &chin_idx.to_le_bytes()],
        &deps.storage,
    );
    let is_jawless = may_load::<u8, _>(&chin_var_map, "None".as_bytes())?.ok_or_else(|| {
        StdError::generic_err("Did not find expected None variant for Jaw Type layer category")
    })? == image[chin_idx as usize];
    let et_var_map = ReadonlyPrefixedStorage::multilevel(
        &[PREFIX_VARIANT_MAP, &eye_type_idx.to_le_bytes()],
        &deps.storage,
    );
    let is_cyclops =
        may_load::<u8, _>(&et_var_map, "EyeType.Cyclops".as_bytes())?.ok_or_else(|| {
            StdError::generic_err(
                "Did not find expected EyeType.Cyclops variant for Eye Type layer category",
            )
        })? == image[eye_type_idx as usize];

    to_binary(&QueryAnswer::SkullType {
        is_cyclops,
        is_jawless,
    })
}

/// Returns QueryResult which provides the info needed by alchemy/reveal contracts
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
fn query_serve_alchemy<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: ViewerInfo,
) -> QueryResult {
    let (querier, _) = get_querier(deps, Some(viewer), None)?;
    // only allow viewers to call this
    let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    if !viewers.contains(&querier) {
        return Err(StdError::unauthorized());
    }
    let state: State = load(&deps.storage, STATE_KEY)?;
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
    let category_names = (0..state.cat_cnt)
        .map(|u| {
            may_load::<Category, _>(&cat_store, &u.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))
                .map(|r| r.name)
        })
        .collect::<StdResult<Vec<String>>>()?;
    let dependencies: Vec<StoredDependencies> =
        may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::ServeAlchemy {
        skip: state.skip,
        dependencies,
        category_names,
    })
}

/// Returns QueryResult displaying the number of categories and which ones are skipped
/// when rolling
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_state<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let state: State = load(&deps.storage, STATE_KEY)?;
    // map indices to string names
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
    let skip = state
        .skip
        .iter()
        .map(|u| {
            may_load::<Category, _>(&cat_store, &u.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))
                .map(|r| r.name)
        })
        .collect::<StdResult<Vec<String>>>()?;

    to_binary(&QueryAnswer::State {
        category_count: state.cat_cnt,
        skip,
    })
}

/// Returns QueryResult displaying the trait variants that require other trait variants
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `start_at` - optional dependency index to start the display
/// * `limit` - optional max number of dependencies to display
fn query_dependencies<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    start_at: Option<u16>,
    limit: Option<u16>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let max = limit.unwrap_or(100);
    let start = start_at.unwrap_or(0);
    let dependencies: Vec<StoredDependencies> =
        may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let count = dependencies.len() as u16;
    to_binary(&QueryAnswer::Dependencies {
        count,
        dependencies: dependencies
            .iter()
            .skip(start as usize)
            .take(max as usize)
            .map(|d| d.to_display(&deps.storage))
            .collect::<StdResult<Vec<Dependencies>>>()?,
    })
}

/// Returns QueryResult displaying a layer variant
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `by_name` - optional reference to the LayerId using string names
/// * `by_index` - optional StoredLayerId using indices
/// * `display_svg` - optionally true if svgs should be displayed
#[allow(clippy::too_many_arguments)]
fn query_variant<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    by_name: Option<&LayerId>,
    by_index: Option<StoredLayerId>,
    display_svg: Option<bool>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let svgs = display_svg.unwrap_or(false);
    let layer_id = if let Some(id) = by_index {
        id
    } else if let Some(id) = by_name {
        id.to_stored(&deps.storage)?
    } else {
        return Err(StdError::generic_err(
            "Must specify a layer ID by either names or indices",
        ));
    };
    // get the dependencies and hiders lists
    let depends: Vec<StoredDependencies> =
        may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let var_inf = displ_variant(&deps.storage, &layer_id, &depends, svgs)?;
    to_binary(&QueryAnswer::Variant {
        category_index: layer_id.category,
        info: var_inf,
    })
}

/// Returns QueryResult displaying a trait category
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `name` - optional name of the category to display
/// * `index` - optional index of the category to display
/// * `start_at` - optional variant index to start the display
/// * `limit` - optional max number of variants to display
/// * `display_svg` - optionally true if svgs should be displayed
#[allow(clippy::too_many_arguments)]
fn query_category<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    name: Option<&str>,
    index: Option<u8>,
    start_at: Option<u8>,
    limit: Option<u8>,
    display_svg: Option<bool>,
) -> QueryResult {
    // only allow admins to do this
    check_admin(deps, viewer, permit)?;
    let svgs = display_svg.unwrap_or(false);
    let max = limit.unwrap_or(if svgs { 5 } else { 30 });
    let start = start_at.unwrap_or(0);
    let state: State = load(&deps.storage, STATE_KEY)?;
    let cat_idx = if let Some(nm) = name {
        let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
        may_load::<u8, _>(&cat_map, nm.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!("Category name:  {} does not exist", nm))
        })?
    } else if let Some(i) = index {
        if i >= state.cat_cnt {
            return Err(StdError::generic_err(format!(
                "There are only {} categories",
                state.cat_cnt
            )));
        }
        i
    } else {
        0u8
    };
    let depends: Vec<StoredDependencies> =
        may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let cat_key = cat_idx.to_le_bytes();
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
    let cat: Category = may_load(&cat_store, &cat_key)?
        .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
    let end = min(start + max, cat.cnt);
    let mut variants: Vec<VariantInfoPlus> = Vec::new();
    for idx in start..end {
        let layer_id = StoredLayerId {
            category: cat_idx,
            variant: idx,
        };
        let var_inf = displ_variant(&deps.storage, &layer_id, &depends, svgs)?;
        variants.push(var_inf);
    }

    to_binary(&QueryAnswer::Category {
        category_count: state.cat_cnt,
        index: cat_idx,
        name: cat.name,
        skip: cat.skip,
        variant_count: cat.cnt,
        variants,
    })
}

/// Returns QueryResult displaying the admin, minter, and viewer lists
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_addresses<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow admins to do this
    let (admins, _) = check_admin(deps, viewer, permit)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    to_binary(&QueryAnswer::AuthorizedAddresses {
        admins: admins
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
        minters: minters
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
        viewers: viewers
            .iter()
            .map(|a| deps.api.human_address(a))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
    })
}

/// Returns QueryResult displaying the metadata for an NFT's image vector
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `image` - list of image indices
fn query_token_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    image: &[u8],
) -> QueryResult {
    // only allow authorized addresses to do this
    let (querier, _) = get_querier(deps, viewer, permit)?;
    let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    if !viewers.contains(&querier) {
        let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
        if !minters.contains(&querier) {
            let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
            if !admins.contains(&querier) {
                return Err(StdError::unauthorized());
            }
        }
    }
    let common: CommonMetadata = may_load(&deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
        public: None,
        private: None,
    });
    let mut public_metadata = common.public.unwrap_or(Metadata {
        token_uri: None,
        extension: None,
    });
    let mut xten = public_metadata.extension.unwrap_or_default();
    let state: State = load(&deps.storage, STATE_KEY)?;
    let mut image_data = r###"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -0.5 24 24" shape-rendering="crispEdges">"###.to_string();
    let mut attributes: Vec<Trait> = Vec::new();
    let cat_store = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY, &deps.storage);
    let mut trait_cnt = 0u8;
    let mut revealed = 0u8;
    let mut none_cnt = 0u8;
    // get the hair category index
    let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, &deps.storage);
    let hair_idx: u8 = may_load(&cat_map, "Hair".as_bytes())?
        .ok_or_else(|| StdError::generic_err("Hair layer category not found"))?;

    for (cat_idx, var_idx) in image.iter().enumerate() {
        let cat_key = (cat_idx as u8).to_le_bytes();
        let cat: Category = may_load(&cat_store, &cat_key)?
            .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
        let disp_trait = !state.skip.contains(&(cat_idx as u8));
        // 255 means not revealed
        if *var_idx != 255 || cat_idx == hair_idx as usize {
            let (mod_var_idx, is_unknown) = if *var_idx == 255 {
                // if this is unknown Hair
                let var_map = ReadonlyPrefixedStorage::multilevel(
                    &[PREFIX_VARIANT_MAP, &cat_key],
                    &deps.storage,
                );
                (
                    may_load(&var_map, "None".as_bytes())?.ok_or_else(|| {
                        StdError::generic_err("Missing None variant of Hair Category")
                    })?,
                    true,
                )
            // otherwise it is just a revealed trait
            } else {
                if disp_trait {
                    revealed += 1;
                }
                (*var_idx, false)
            };
            let var_store =
                ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &cat_key], &deps.storage);
            let var: VariantInfo = may_load(&var_store, &mod_var_idx.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
            image_data.push_str(&var.svg.unwrap_or_default());
            let value = if is_unknown {
                "???".to_string()
            } else {
                var.display_name
            };
            if disp_trait {
                // tally the Nones
                if value == *"None" {
                    none_cnt += 1;
                }
                attributes.push(Trait {
                    display_type: None,
                    trait_type: Some(cat.name),
                    value,
                    max_value: None,
                });
                trait_cnt += 1;
            }
        } else if disp_trait {
            attributes.push(Trait {
                display_type: None,
                trait_type: Some(cat.name),
                value: "???".to_string(),
                max_value: None,
            });
            trait_cnt += 1;
        }
    }
    let hidden = trait_cnt - revealed;
    attributes.push(Trait {
        display_type: None,
        trait_type: Some("Unrevealed Trait Categories".to_string()),
        value: format!("{}", hidden),
        max_value: None,
    });
    // display the trait count if fully revealed
    if hidden == 0 {
        attributes.push(Trait {
            display_type: None,
            trait_type: Some("Trait Count".to_string()),
            value: format!("{}", trait_cnt - none_cnt),
            max_value: None,
        });
    } else {
        // count of nones if there are still unrevealed traits
        attributes.push(Trait {
            display_type: None,
            trait_type: Some("Clean Traits (Nones) Currently Revealed".to_string()),
            value: format!("{}", none_cnt),
            max_value: None,
        });
    }
    // set the alchemical status
    let value = if image[0] > 5 {
        "Transmuted".to_string()
    } else {
        "Raw".to_string()
    };
    attributes.push(Trait {
        display_type: None,
        trait_type: Some("Alchemical Status".to_string()),
        value,
        max_value: None,
    });
    image_data.push_str("</svg>");
    xten.image_data = Some(image_data);
    xten.attributes = Some(attributes);
    public_metadata.extension = Some(xten);

    to_binary(&QueryAnswer::Metadata {
        public_metadata: Some(public_metadata),
        private_metadata: common.private,
    })
}

/// Returns QueryResult displaying the metadata common to all NFTs
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
fn query_common_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
) -> QueryResult {
    // only allow authorized addresses to do this
    let (querier, _) = get_querier(deps, viewer, permit)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&querier) {
        let viewers: Vec<CanonicalAddr> = may_load(&deps.storage, VIEWERS_KEY)?.unwrap_or_default();
        if !viewers.contains(&querier) {
            let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
            if !admins.contains(&querier) {
                return Err(StdError::unauthorized());
            }
        }
    }
    let common: CommonMetadata = may_load(&deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
        public: None,
        private: None,
    });

    to_binary(&QueryAnswer::Metadata {
        public_metadata: common.public,
        private_metadata: common.private,
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
        let me_raw: CanonicalAddr = may_load(&deps.storage, MY_ADDRESS_KEY)?.ok_or_else(|| {
            StdError::generic_err("Svg server contract address storage is corrupt")
        })?;
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

/// Returns StdResult<(Vec<CanonicalAddr>, Option<CanonicalAddr>)> which is the admin list
/// and this contract's address if it has been retrieved, and checks if the querier is an admin
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
    let (admin, my_addr) = get_querier(deps, viewer, permit)?;
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    if !admins.contains(&admin) {
        return Err(StdError::unauthorized());
    }
    Ok((admins, my_addr))
}

pub enum AddrType {
    Admin,
    Viewer,
    Minter,
}

/// Returns HandleResult
///
/// updates the admin, viewer, or minter authorization list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `update_list` - list of addresses to use for update
/// * `is_add` - true if the update is for adding to the list
/// * `list` - AddrType to determine which list to update
fn try_process_auth_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    update_list: &[HumanAddr],
    is_add: bool,
    list: AddrType,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    // get the right authorization list info
    let (mut current_list, key) = match list {
        AddrType::Admin => (admins, ADMINS_KEY),
        AddrType::Viewer => (
            may_load::<Vec<CanonicalAddr>, _>(&deps.storage, VIEWERS_KEY)?.unwrap_or_default(),
            VIEWERS_KEY,
        ),
        AddrType::Minter => (
            may_load::<Vec<CanonicalAddr>, _>(&deps.storage, MINTERS_KEY)?.unwrap_or_default(),
            MINTERS_KEY,
        ),
    };
    // update the authorization list if needed
    let save_it = if is_add {
        add_addrs_to_auth(&deps.api, &mut current_list, update_list)?
    } else {
        remove_addrs_from_auth(&deps.api, &mut current_list, update_list)?
    };
    // save list if it changed
    if save_it {
        save(&mut deps.storage, key, &current_list)?;
    }
    let new_list = current_list
        .iter()
        .map(|a| deps.api.human_address(a))
        .collect::<StdResult<Vec<HumanAddr>>>()?;
    let resp = match list {
        AddrType::Admin => HandleAnswer::AdminsList { admins: new_list },
        AddrType::Viewer => HandleAnswer::ViewersList { viewers: new_list },
        AddrType::Minter => HandleAnswer::MintersList { minters: new_list },
    };
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&resp)?),
    })
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
fn add_addrs_to_auth<A: Api>(
    api: &A,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_add: &[HumanAddr],
) -> StdResult<bool> {
    let mut save_it = false;
    for addr in addrs_to_add.iter() {
        let raw = api.canonical_address(addr)?;
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
fn remove_addrs_from_auth<A: Api>(
    api: &A,
    addresses: &mut Vec<CanonicalAddr>,
    addrs_to_remove: &[HumanAddr],
) -> StdResult<bool> {
    let old_len = addresses.len();
    let rem_list = addrs_to_remove
        .iter()
        .map(|a| api.canonical_address(a))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    addresses.retain(|a| !rem_list.contains(a));
    // only save if the list changed
    Ok(old_len != addresses.len())
}

/// Returns StdResult<()>
///
/// adds new trait variants to the specified category index
///
/// # Arguments
///
/// * `storage` - a mutable reference to the contract's storage
/// * `cat_key` - index of the category these variants belong to
/// * `variants` - variants to add to this category
/// * `cat` - a mutable reference to this trait category
#[allow(clippy::too_many_arguments)]
fn add_variants<S: Storage>(
    storage: &mut S,
    cat_key: &[u8],
    variants: Vec<VariantInfo>,
    cat: &mut Category,
) -> StdResult<()> {
    for var in variants.into_iter() {
        let var_name_key = var.name.as_bytes();
        let mut var_map = PrefixedStorage::multilevel(&[PREFIX_VARIANT_MAP, cat_key], storage);
        if may_load::<u8, _>(&var_map, var_name_key)?.is_some() {
            return Err(StdError::generic_err(format!(
                "Variant name:  {} already exists under category:  {}",
                &var.name, &cat.name
            )));
        }
        save(&mut var_map, var_name_key, &cat.cnt)?;
        let mut var_store = PrefixedStorage::multilevel(&[PREFIX_VARIANT, cat_key], storage);
        save(&mut var_store, &cat.cnt.to_le_bytes(), &var)?;
        cat.cnt = cat.cnt.checked_add(1).ok_or_else(|| {
            StdError::generic_err(format!(
                "Reached maximum number of variants for category: {}",
                &cat.name
            ))
        })?;
    }
    Ok(())
}

/// Returns StdResult<Option<Metadata>>
///
/// filter metadata to error if both token_uri and extension are present, or to be
/// None if neither are present
///
/// # Arguments
///
/// * `metadata` - Metadata being screened
fn filter_metadata(metadata: Metadata) -> StdResult<Option<Metadata>> {
    let has_uri = metadata.token_uri.is_some();
    let has_xten = metadata.extension.is_some();
    // if you have both or have neither
    let new_meta = if has_uri == has_xten {
        // if both
        if has_uri {
            return Err(StdError::generic_err(
                "Metadata can not have BOTH token_uri AND extension",
            ));
        }
        // delete the existing if all fields are None
        None
    } else {
        Some(metadata)
    };
    Ok(new_meta)
}

pub enum Action {
    Add,
    Remove,
    Modify,
}

/// Returns HandleResult
///
/// updates the dependencies list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `update_list` - list of dependencies to use for update
/// * `action` - Action to perform on the dependency list
fn try_process_dep_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &HumanAddr,
    update_list: &[Dependencies],
    action: Action,
) -> HandleResult {
    // only allow admins to do this
    let admins: Vec<CanonicalAddr> = load(&deps.storage, ADMINS_KEY)?;
    let sender_raw = deps.api.canonical_address(sender)?;
    if !admins.contains(&sender_raw) {
        return Err(StdError::unauthorized());
    }
    let mut depends: Vec<StoredDependencies> =
        may_load(&deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let mut save_dep = false;
    let status = "success".to_string();
    let resp = match action {
        Action::Add => {
            for dep in update_list.iter() {
                let stored = dep.to_stored(&deps.storage)?;
                // add if this variant does not already have dependencies
                if !depends.iter().any(|d| d.id == stored.id) {
                    depends.push(stored);
                    save_dep = true;
                }
            }
            HandleAnswer::AddDependencies { status }
        }
        Action::Remove => {
            let old_len = depends.len();
            let rem_list = update_list
                .iter()
                .map(|d| d.to_stored(&deps.storage))
                .collect::<StdResult<Vec<StoredDependencies>>>()?;
            depends.retain(|d| !rem_list.iter().any(|r| r.id == d.id));
            // only save if the list changed
            if old_len != depends.len() {
                save_dep = true;
            }
            HandleAnswer::RemoveDependencies { status }
        }
        Action::Modify => {
            for dep in update_list.iter() {
                let stored = dep.to_stored(&deps.storage)?;
                let existing = depends.iter_mut().find(|d| d.id == stored.id);
                if let Some(update) = existing {
                    *update = stored;
                    save_dep = true;
                } else {
                    return Err(StdError::generic_err(format!(
                        "No existing dependencies for Variant: {} in Category: {}",
                        dep.id.variant, dep.id.category
                    )));
                }
            }
            HandleAnswer::ModifyDependencies { status }
        }
    };
    if save_dep {
        save(&mut deps.storage, DEPENDENCIES_KEY, &depends)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&resp)?),
    })
}

/// used to cache index lookups
#[derive(Clone)]
pub struct BackCache {
    pub id: String,
    pub index: u8,
}

/// Returns StdResult<VariantInfoPlus>
///
/// creates the VariantInfoPlus of a specified layer variant
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `id` - a reference to the StoredLayerId of the variant to display
/// * `depends` - list of traits that have multiple layers
/// * `svgs` - true if svgs should be displayed
fn displ_variant<S: ReadonlyStorage>(
    storage: &S,
    id: &StoredLayerId,
    depends: &[StoredDependencies],
    svgs: bool,
) -> StdResult<VariantInfoPlus> {
    let var_store =
        ReadonlyPrefixedStorage::multilevel(&[PREFIX_VARIANT, &id.category.to_le_bytes()], storage);
    // see if this variant requires other layer variants
    let includes = if let Some(dep) = depends.iter().find(|d| d.id == *id) {
        dep.correlated
            .iter()
            .map(|l| l.to_display(storage))
            .collect::<StdResult<Vec<LayerId>>>()?
    } else {
        Vec::new()
    };
    let mut variant_info: VariantInfo = may_load(&var_store, &id.variant.to_le_bytes())?
        .ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
    if !svgs {
        variant_info.svg = None;
    }
    let var_plus = VariantInfoPlus {
        index: id.variant,
        variant_info,
        includes,
    };
    Ok(var_plus)
}

/// Returns StdResult<u8>
///
/// either retrieves a known cat/variant's index or determines it and adds it to
/// the cache
///
/// # Arguments
///
/// * `map` - a reference to the cat/variant map
/// * `id` - cat/variant name
/// * `back_cache` - a mutable reference to the cat/variant name cache
fn use_back_cache<S: ReadonlyStorage>(
    map: &S,
    id: &str,
    back_cache: &mut Vec<BackCache>,
) -> StdResult<u8> {
    if let Some(bg) = back_cache.iter().find(|b| b.id == id) {
        Ok(bg.index)
    } else {
        let index: u8 = may_load(map, id.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!("Did not find a category/variant named {}", id))
        })?;
        let entry = BackCache {
            id: id.to_string(),
            index,
        };
        back_cache.push(entry);
        Ok(index)
    }
}

/// Returns StdResult<()>
///
/// replaces a layer in the image, honoring dependencies as needed
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `image` - a mutable reference to the image indices
/// * `new_layer` - a reference to the new image variant
/// * `dependencies` - slice of the definied dependencies
/// * `cat_cache` - a mutable reference to the BackCache of categories
/// * `var_caches` - a mutable reference to the Vec of BackCaches of variants
fn replace_layer<S: ReadonlyStorage>(
    storage: &S,
    image: &mut [u8],
    new_layer: &LayerId,
    dependencies: &[StoredDependencies],
    cat_cache: &mut Vec<BackCache>,
    var_caches: &mut [Vec<BackCache>],
) -> StdResult<()> {
    let cat_map = ReadonlyPrefixedStorage::new(PREFIX_CATEGORY_MAP, storage);
    // if processing a Skull variant
    if new_layer.category == "Skull" {
        let skull_idx = use_back_cache(&cat_map, "Skull", cat_cache)?;
        let skull_var_map = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_VARIANT_MAP, &skull_idx.to_le_bytes()],
            storage,
        );
        let skull_cache = var_caches
            .get_mut(skull_idx as usize)
            .ok_or_else(|| StdError::generic_err("Variant caches improperly initialized"))?;
        let new_skull_var_idx = use_back_cache(&skull_var_map, &new_layer.variant, skull_cache)?;
        // if the skull is changing color
        if image[skull_idx as usize] != new_skull_var_idx {
            let chin_idx = use_back_cache(&cat_map, "Jaw Type", cat_cache)?;
            let chin_var_map = ReadonlyPrefixedStorage::multilevel(
                &[PREFIX_VARIANT_MAP, &chin_idx.to_le_bytes()],
                storage,
            );
            let chin_cache = var_caches
                .get_mut(chin_idx as usize)
                .ok_or_else(|| StdError::generic_err("Variant caches improperly initialized"))?;
            let jawless_idx = use_back_cache(&chin_var_map, "None", chin_cache)?;
            // if not jawless
            if image[chin_idx as usize] != jawless_idx {
                // get the same jaw color as the skull
                image[chin_idx as usize] =
                    use_back_cache(&chin_var_map, &new_layer.variant, chin_cache)?;
            }
            // update the skull color
            image[skull_idx as usize] = new_skull_var_idx;
        }
    // any category except Skull
    } else {
        let cat_idx = use_back_cache(&cat_map, &new_layer.category, cat_cache)?;
        let var_map = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_VARIANT_MAP, &cat_idx.to_le_bytes()],
            storage,
        );
        let var_cache = var_caches
            .get_mut(cat_idx as usize)
            .ok_or_else(|| StdError::generic_err("Variant caches improperly initialized"))?;
        let new_stored_layer = StoredLayerId {
            category: cat_idx,
            variant: use_back_cache(&var_map, &new_layer.variant, var_cache)?,
        };
        let old_stored_layer = StoredLayerId {
            category: cat_idx,
            variant: image[cat_idx as usize],
        };
        // only process if the variant is changing
        if new_stored_layer.variant != old_stored_layer.variant {
            // see if the old variant has dependencies that need to be cleared
            if let Some(depends) = dependencies.iter().find(|d| d.id == old_stored_layer) {
                for dep in depends.correlated.iter() {
                    // set each dependency layer to None
                    let dep_var_map = ReadonlyPrefixedStorage::multilevel(
                        &[PREFIX_VARIANT_MAP, &dep.category.to_le_bytes()],
                        storage,
                    );
                    let dep_var_cache =
                        var_caches.get_mut(dep.category as usize).ok_or_else(|| {
                            StdError::generic_err("Variant caches improperly initialized")
                        })?;
                    image[dep.category as usize] =
                        use_back_cache(&dep_var_map, "None", dep_var_cache)?;
                }
            }
            // see if the new variant has dependencies that need to be set
            if let Some(depends) = dependencies.iter().find(|d| d.id == new_stored_layer) {
                for dep in depends.correlated.iter() {
                    image[dep.category as usize] = dep.variant;
                }
            }
            // set the new layer
            image[new_stored_layer.category as usize] = new_stored_layer.variant;
        }
    }
    Ok(())
}
