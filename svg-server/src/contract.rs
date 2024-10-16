use base64::{engine::general_purpose, Engine as _};
use cosmwasm_std::{
    entry_point, to_binary, Addr, Api, Binary, CanonicalAddr, Deps, DepsMut, Env, MessageInfo,
    Response, StdError, StdResult, Storage,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::min;

use secret_toolkit::{
    crypto::sha_256,
    permit::{validate, Permit, RevokedPermits},
    utils::{pad_handle_result, pad_query_result},
    viewing_key::{ViewingKey, ViewingKeyStore},
};

use crate::metadata::{Metadata, Trait};
use crate::msg::{
    AddVariantInfo, CategoryInfo, CommonMetadata, Dependencies, ExecuteAnswer, ExecuteMsg,
    InstantiateMsg, LayerId, QueryAnswer, QueryMsg, StoredDependencies, StoredLayerId,
    VariantIdxName, VariantInfo, VariantInfoPlus, VariantModInfo, ViewerInfo,
};
use crate::state::{
    Category, State, ADMINS_KEY, DEPENDENCIES_KEY, METADATA_KEY, MINTERS_KEY, PREFIX_CATEGORY,
    PREFIX_CATEGORY_MAP, PREFIX_REVOKED_PERMITS, PREFIX_VARIANT, PREFIX_VARIANT_MAP, STATE_KEY,
    VIEWERS_KEY,
};
use crate::storage::{load, may_load, remove, save};

pub const BLOCK_SIZE: usize = 256;

////////////////////////////////////// Instantiate ///////////////////////////////////////
/// Returns StdResult<Response>
///
/// Initializes the server contract
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
    _env: Env,
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
    let mut admins = vec![sender_raw];
    if let Some(addrs) = msg.admins {
        add_addrs_to_auth(deps.api, &mut admins, &addrs)?;
    }
    save(deps.storage, ADMINS_KEY, &admins)?;
    let state = State {
        cat_cnt: 0u8,
        skip: Vec::new(),
    };
    save(deps.storage, STATE_KEY, &state)?;

    Ok(Response::default())
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
        ExecuteMsg::AddCategories { categories } => {
            try_add_categories(deps, &info.sender, categories)
        }
        ExecuteMsg::AddVariants { variants } => try_add_variants(deps, &info.sender, variants),
        ExecuteMsg::ModifyCategory {
            name,
            new_name,
            new_skip,
        } => try_modify_category(deps, &info.sender, &name, new_name, new_skip),
        ExecuteMsg::ModifyVariants { modifications } => {
            try_modify_variants(deps, &info.sender, modifications)
        }
        ExecuteMsg::SetMetadata {
            public_metadata,
            private_metadata,
        } => try_set_metadata(deps, &info.sender, public_metadata, private_metadata),
        ExecuteMsg::AddAdmins { admins } => {
            try_process_auth_list(deps, &info.sender, &admins, true, AddrType::Admin)
        }
        ExecuteMsg::RemoveAdmins { admins } => {
            try_process_auth_list(deps, &info.sender, &admins, false, AddrType::Admin)
        }
        ExecuteMsg::AddViewers { viewers } => {
            try_process_auth_list(deps, &info.sender, &viewers, true, AddrType::Viewer)
        }
        ExecuteMsg::RemoveViewers { viewers } => {
            try_process_auth_list(deps, &info.sender, &viewers, false, AddrType::Viewer)
        }
        ExecuteMsg::AddMinters { minters } => {
            try_process_auth_list(deps, &info.sender, &minters, true, AddrType::Minter)
        }
        ExecuteMsg::RemoveMinters { minters } => {
            try_process_auth_list(deps, &info.sender, &minters, false, AddrType::Minter)
        }
        ExecuteMsg::AddDependencies { dependencies } => {
            try_process_dep_list(deps, &info.sender, &dependencies, Action::Add)
        }
        ExecuteMsg::RemoveDependencies { dependencies } => {
            try_process_dep_list(deps, &info.sender, &dependencies, Action::Remove)
        }
        ExecuteMsg::ModifyDependencies { dependencies } => {
            try_process_dep_list(deps, &info.sender, &dependencies, Action::Modify)
        }
        ExecuteMsg::RevokePermit { permit_name } => {
            revoke_permit(deps.storage, &info.sender, &permit_name)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns StdResult<Response>
///
/// sets the common metadata for all NFTs
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `public_metadata` - optional public metadata used for all NFTs
/// * `private_metadata` - optional private metadata used for all NFTs
fn try_set_metadata(
    deps: DepsMut,
    sender: &Addr,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut common: CommonMetadata =
        may_load(deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
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
            remove(deps.storage, METADATA_KEY);
        } else {
            save(deps.storage, METADATA_KEY, &common)?;
        }
    }
    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::SetMetadata { metadata: common })?))
}

/// Returns StdResult<Response>
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
fn try_modify_category(
    deps: DepsMut,
    sender: &Addr,
    name: &str,
    new_name: Option<String>,
    new_skip: Option<bool>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let cat_name_key = name.as_bytes();
    let mut cat_map = PrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
    if let Some(cat_idx) = may_load::<u8>(&cat_map, cat_name_key)? {
        let mut save_cat = false;
        let cat_key = cat_idx.to_le_bytes();
        let mut may_cat: Option<Category> = None;
        if let Some(new_nm) = new_name {
            if new_nm != name {
                // remove the mapping for the old name
                remove(&mut cat_map, cat_name_key);
                // map the category idx to the new name
                save(&mut cat_map, new_nm.as_bytes(), &cat_idx)?;
                let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
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
                    let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
                    may_load::<Category>(&cat_store, &cat_key)?.ok_or_else(|| {
                        StdError::generic_err(format!("Category storage for {} is corrupt", name))
                    })
                },
                Ok,
            )?;
            if cat.skip != skip {
                let mut state: State = load(deps.storage, STATE_KEY)?;
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
                    save(deps.storage, STATE_KEY, &state)?;
                }
                cat.skip = skip;
                save_cat = true;
            }
            may_cat = Some(cat);
        }
        if save_cat {
            let mut cat_store = PrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
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

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::ModifyCategory {
            status: "success".to_string(),
        })?),
    )
}

/// Returns StdResult<Response>
///
/// adds new trait categories
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `categories` - the new trait categories
fn try_add_categories(
    deps: DepsMut,
    sender: &Addr,
    categories: Vec<CategoryInfo>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut state: State = load(deps.storage, STATE_KEY)?;
    for cat_inf in categories.into_iter() {
        let cat_name_key = cat_inf.name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
        if may_load::<u8>(&cat_map, cat_name_key)?.is_some() {
            return Err(StdError::generic_err(format!(
                "Category name:  {} already exists",
                cat_inf.name
            )));
        }
        // add the entry to the category map for this category name
        let mut cat_map = PrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
        save(&mut cat_map, cat_name_key, &state.cat_cnt)?;
        let cat_key = state.cat_cnt.to_le_bytes();
        let mut cat = Category {
            name: cat_inf.name,
            skip: cat_inf.skip,
            cnt: 0,
        };
        add_variants(deps.storage, &cat_key, cat_inf.variants, &mut cat)?;
        let mut cat_store = PrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
        save(&mut cat_store, &cat_key, &cat)?;
        state.cat_cnt = state
            .cat_cnt
            .checked_add(1)
            .ok_or_else(|| StdError::generic_err("Reached maximum number of trait categories"))?;
    }
    save(deps.storage, STATE_KEY, &state)?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::AddCategories {
            count: state.cat_cnt,
        })?),
    )
}

/// Returns StdResult<Response>
///
/// modifies existing trait variants
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `modifications` - the updated trait variants and the categories they belong to
fn try_modify_variants(
    deps: DepsMut,
    sender: &Addr,
    modifications: Vec<VariantModInfo>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    for cat_inf in modifications.into_iter() {
        let cat_name = cat_inf.category;
        let cat_name_key = cat_name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
        // if valid category name
        if let Some(cat_idx) = may_load::<u8>(&cat_map, cat_name_key)? {
            let cat_key = cat_idx.to_le_bytes();
            for var_mod in cat_inf.modifications.into_iter() {
                let var_name_key = var_mod.name.as_bytes();
                let mut var_map =
                    PrefixedStorage::multilevel(deps.storage, &[PREFIX_VARIANT_MAP, &cat_key]);
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
                    PrefixedStorage::multilevel(deps.storage, &[PREFIX_VARIANT, &cat_key]);
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

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::ModifyVariants {
            status: "success".to_string(),
        })?),
    )
}

/// Returns StdResult<Response>
///
/// adds new trait variants to existing categories
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `variants` - the new trait variants and the categories they belong to
fn try_add_variants(
    deps: DepsMut,
    sender: &Addr,
    variants: Vec<AddVariantInfo>,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    for cat_inf in variants.into_iter() {
        let cat_name_key = cat_inf.category_name.as_bytes();
        let cat_map = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
        if let Some(cat_idx) = may_load::<u8>(&cat_map, cat_name_key)? {
            let cat_key = cat_idx.to_le_bytes();
            let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
            let mut cat: Category = may_load(&cat_store, &cat_key)?.ok_or_else(|| {
                StdError::generic_err(format!(
                    "Category storage for {} is corrupt",
                    cat_inf.category_name
                ))
            })?;
            add_variants(deps.storage, &cat_key, cat_inf.variants, &mut cat)?;
            let mut cat_store = PrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
            save(&mut cat_store, &cat_key, &cat)?;
        } else {
            return Err(StdError::generic_err(format!(
                "Category name:  {} does not exist",
                cat_inf.category_name
            )));
        }
    }

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::AddVariants {
            status: "success".to_string(),
        })?),
    )
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
        QueryMsg::AuthorizedAddresses { viewer, permit } => {
            query_addresses(deps, viewer, permit, &env.contract.address)
        }
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
            &env.contract.address,
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
            &env.contract.address,
        ),
        QueryMsg::CommonMetadata { viewer, permit } => {
            query_common_metadata(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::State { viewer, permit } => {
            query_state(deps, viewer, permit, &env.contract.address)
        }
        QueryMsg::Dependencies {
            viewer,
            permit,
            start_at,
            limit,
        } => query_dependencies(deps, viewer, permit, start_at, limit, &env.contract.address),
        QueryMsg::TokenMetadata {
            viewer,
            permit,
            image,
        } => query_token_metadata(deps, viewer, permit, &image, &env.contract.address),
        QueryMsg::ServeAlchemy { viewer } => query_serve_alchemy(deps, viewer),
        QueryMsg::SkullType { viewer, image } => query_skull_type(deps, viewer, &image),
        QueryMsg::SkullTypePlus { viewer } => query_type_plus(deps, viewer),
        QueryMsg::Transmute {
            viewer,
            current,
            new_layers,
        } => query_transmute(deps, viewer, current, &new_layers),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns StdResult<Binary> which displays the new image vec after transmuting as requested
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
/// * `current` - the current image indices
/// * `new_layers` - the new image layers to incorporate
fn query_transmute(
    deps: Deps,
    viewer: ViewerInfo,
    mut current: Vec<u8>,
    new_layers: &[LayerId],
) -> StdResult<Binary> {
    // only allow viewers to call this
    check_viewer(deps, viewer)?;

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
            ReadonlyPrefixedStorage::multilevel(deps.storage, &[PREFIX_VARIANT, &back_idx_key]);
        let var: VariantInfo = may_load(&back_var_store, &current[0].to_le_bytes())?
            .ok_or_else(|| StdError::generic_err("Variant storage is corrupt"))?;
        let new_back = format!("Background.{}.Transmuted", &var.display_name);
        let back_var_map =
            ReadonlyPrefixedStorage::multilevel(deps.storage, &[PREFIX_VARIANT_MAP, &back_idx_key]);
        current[0] = may_load(&back_var_map, new_back.as_bytes())?.ok_or_else(|| {
            StdError::generic_err(format!("Did not find Background variant {}", &new_back))
        })?;
    }
    let dependencies: Vec<StoredDependencies> =
        may_load(deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let state: State = load(deps.storage, STATE_KEY)?;
    let mut cat_cache: Vec<BackCache> = Vec::new();
    let mut var_caches: Vec<Vec<BackCache>> = vec![Vec::new(); state.cat_cnt as usize];
    // update each requested layer
    for layer in new_layers.iter() {
        replace_layer(
            deps.storage,
            &mut current,
            layer,
            &dependencies,
            &mut cat_cache,
            &mut var_caches,
        )?;
    }

    to_binary(&QueryAnswer::Transmute { image: current })
}

/// Returns StdResult<Binary> which displays if a skull is a cyclops and if it is jawless
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
/// * `image` - the image indices
fn query_skull_type(deps: Deps, viewer: ViewerInfo, image: &[u8]) -> StdResult<Binary> {
    // only allow viewers to call this
    check_viewer(deps, viewer)?;
    let (cyclops, jawless) = get_type_layers(deps.storage)?;

    let is_jawless = image[jawless.category as usize] == jawless.variant;
    let is_cyclops = image[cyclops.category as usize] == cyclops.variant;

    to_binary(&QueryAnswer::SkullType {
        is_cyclops,
        is_jawless,
    })
}

/// Returns StdResult<Binary> which displays the StoredLayerIds for cyclops and jawless
/// and displays all skull materials and their indices
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
fn query_type_plus(deps: Deps, viewer: ViewerInfo) -> StdResult<Binary> {
    // only allow viewers to call this
    check_viewer(deps, viewer)?;
    // get cyclops and jawless layers
    let (cyclops, jawless) = get_type_layers(deps.storage)?;
    // get the skull index
    let cat_map = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
    let skull_idx: u8 = may_load(&cat_map, "Skull".as_bytes())?
        .ok_or_else(|| StdError::generic_err("Skull layer category not found"))?;
    let skull_key = skull_idx.to_le_bytes();
    // get the skull category
    let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
    let cat: Category = may_load(&cat_store, &skull_key)?
        .ok_or_else(|| StdError::generic_err("Skull Category storage is corrupt"))?;
    let var_store =
        ReadonlyPrefixedStorage::multilevel(deps.storage, &[PREFIX_VARIANT, &skull_key]);
    let mut skull_variants: Vec<VariantIdxName> = Vec::new();
    for idx in 0..cat.cnt {
        let variant_info: VariantInfo = may_load(&var_store, &idx.to_le_bytes())?
            .ok_or_else(|| StdError::generic_err("Skull Variant storage is corrupt"))?;
        skull_variants.push(VariantIdxName {
            idx,
            name: variant_info.display_name,
        });
    }

    to_binary(&QueryAnswer::SkullTypePlus {
        cyclops,
        jawless,
        skull_idx,
        skull_variants,
    })
}

/// Returns StdResult<Binary> which provides the info needed by alchemy/reveal contracts
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
fn query_serve_alchemy(deps: Deps, viewer: ViewerInfo) -> StdResult<Binary> {
    // only allow viewers to call this
    check_viewer(deps, viewer)?;

    let state: State = load(deps.storage, STATE_KEY)?;
    let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
    let category_names = (0..state.cat_cnt)
        .map(|u| {
            may_load::<Category>(&cat_store, &u.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))
                .map(|r| r.name)
        })
        .collect::<StdResult<Vec<String>>>()?;
    let dependencies: Vec<StoredDependencies> =
        may_load(deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();

    to_binary(&QueryAnswer::ServeAlchemy {
        skip: state.skip,
        dependencies,
        category_names,
    })
}

/// Returns StdResult<Binary> displaying the number of categories and which ones are skipped
/// when rolling
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
    let state: State = load(deps.storage, STATE_KEY)?;
    // map indices to string names
    let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
    let skip = state
        .skip
        .iter()
        .map(|u| {
            may_load::<Category>(&cat_store, &u.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))
                .map(|r| r.name)
        })
        .collect::<StdResult<Vec<String>>>()?;

    to_binary(&QueryAnswer::State {
        category_count: state.cat_cnt,
        skip,
    })
}

/// Returns StdResult<Binary> displaying the trait variants that require other trait variants
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `start_at` - optional dependency index to start the display
/// * `limit` - optional max number of dependencies to display
/// * `my_addr` - a reference to this contract's address
fn query_dependencies(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    start_at: Option<u16>,
    limit: Option<u16>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let max = limit.unwrap_or(100);
    let start = start_at.unwrap_or(0);
    let dependencies: Vec<StoredDependencies> =
        may_load(deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let count = dependencies.len() as u16;
    to_binary(&QueryAnswer::Dependencies {
        count,
        dependencies: dependencies
            .iter()
            .skip(start as usize)
            .take(max as usize)
            .map(|d| d.to_display(deps.storage))
            .collect::<StdResult<Vec<Dependencies>>>()?,
    })
}

/// Returns StdResult<Binary> displaying a layer variant
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `by_name` - optional reference to the LayerId using string names
/// * `by_index` - optional StoredLayerId using indices
/// * `display_svg` - optionally true if svgs should be displayed
/// * `my_addr` - a reference to this contract's address
fn query_variant(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    by_name: Option<&LayerId>,
    by_index: Option<StoredLayerId>,
    display_svg: Option<bool>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let svgs = display_svg.unwrap_or(false);
    let layer_id = if let Some(id) = by_index {
        id
    } else if let Some(id) = by_name {
        id.to_stored(deps.storage)?
    } else {
        return Err(StdError::generic_err(
            "Must specify a layer ID by either names or indices",
        ));
    };
    // get the dependencies and hiders lists
    let depends: Vec<StoredDependencies> =
        may_load(deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let var_inf = displ_variant(deps.storage, &layer_id, &depends, svgs)?;
    to_binary(&QueryAnswer::Variant {
        category_index: layer_id.category,
        info: var_inf,
    })
}

/// Returns StdResult<Binary> displaying a trait category
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
/// * `my_addr` - a reference to this contract's address
fn query_category(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    name: Option<&str>,
    index: Option<u8>,
    start_at: Option<u8>,
    limit: Option<u8>,
    display_svg: Option<bool>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    check_admin_query(deps, viewer, permit, my_addr)?;
    let svgs = display_svg.unwrap_or(false);
    let max = limit.unwrap_or(if svgs { 5 } else { 30 });
    let start = start_at.unwrap_or(0);
    let state: State = load(deps.storage, STATE_KEY)?;
    let cat_idx = if let Some(nm) = name {
        let cat_map = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
        may_load::<u8>(&cat_map, nm.as_bytes())?.ok_or_else(|| {
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
        may_load(deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let cat_key = cat_idx.to_le_bytes();
    let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
    let cat: Category = may_load(&cat_store, &cat_key)?
        .ok_or_else(|| StdError::generic_err("Category storage is corrupt"))?;
    let end = min(start + max, cat.cnt);
    let mut variants: Vec<VariantInfoPlus> = Vec::new();
    for idx in start..end {
        let layer_id = StoredLayerId {
            category: cat_idx,
            variant: idx,
        };
        let var_inf = displ_variant(deps.storage, &layer_id, &depends, svgs)?;
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

/// Returns StdResult<Binary> displaying the admin, minter, and viewer lists
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_addresses(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow admins to do this
    let admins = check_admin_query(deps, viewer, permit, my_addr)?;
    let minters: Vec<CanonicalAddr> = may_load(deps.storage, MINTERS_KEY)?.unwrap_or_default();
    let viewers: Vec<CanonicalAddr> = may_load(deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    to_binary(&QueryAnswer::AuthorizedAddresses {
        admins: admins
            .iter()
            .map(|a| deps.api.addr_humanize(a))
            .collect::<StdResult<Vec<Addr>>>()?,
        minters: minters
            .iter()
            .map(|a| deps.api.addr_humanize(a))
            .collect::<StdResult<Vec<Addr>>>()?,
        viewers: viewers
            .iter()
            .map(|a| deps.api.addr_humanize(a))
            .collect::<StdResult<Vec<Addr>>>()?,
    })
}

/// Returns StdResult<Binary> displaying the metadata for an NFT's image vector
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `image` - list of image indices
/// * `my_addr` - a reference to this contract's address
fn query_token_metadata(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    image: &[u8],
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow authorized addresses to do this
    let querier = get_querier(deps, viewer, permit, my_addr)?;
    let viewers: Vec<CanonicalAddr> = may_load(deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    if !viewers.contains(&querier) {
        let minters: Vec<CanonicalAddr> = may_load(deps.storage, MINTERS_KEY)?.unwrap_or_default();
        if !minters.contains(&querier) {
            let admins: Vec<CanonicalAddr> = load(deps.storage, ADMINS_KEY)?;
            if !admins.contains(&querier) {
                return Err(StdError::generic_err("Not authorized"));
            }
        }
    }
    let common: CommonMetadata = may_load(deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
        public: None,
        private: None,
    });
    let mut public_metadata = common.public.unwrap_or(Metadata {
        token_uri: None,
        extension: None,
    });
    let mut xten = public_metadata.extension.unwrap_or_default();
    let state: State = load(deps.storage, STATE_KEY)?;
    let mut image_data = r###"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -0.5 24 24" shape-rendering="crispEdges">"###.to_string();
    let mut attributes: Vec<Trait> = Vec::new();
    let cat_store = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY);
    let mut trait_cnt = 0u8;
    let mut revealed = 0u8;
    let mut none_cnt = 0u8;
    // get the hair category index
    let cat_map = ReadonlyPrefixedStorage::new(deps.storage, PREFIX_CATEGORY_MAP);
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
                    deps.storage,
                    &[PREFIX_VARIANT_MAP, &cat_key],
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
                ReadonlyPrefixedStorage::multilevel(deps.storage, &[PREFIX_VARIANT, &cat_key]);
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

/// Returns StdResult<Binary> displaying the metadata common to all NFTs
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `permit` - optional permit with "owner" permission
/// * `my_addr` - a reference to this contract's address
fn query_common_metadata(
    deps: Deps,
    viewer: Option<ViewerInfo>,
    permit: Option<Permit>,
    my_addr: &Addr,
) -> StdResult<Binary> {
    // only allow authorized addresses to do this
    let querier = get_querier(deps, viewer, permit, my_addr)?;
    let minters: Vec<CanonicalAddr> = may_load(deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&querier) {
        let viewers: Vec<CanonicalAddr> = may_load(deps.storage, VIEWERS_KEY)?.unwrap_or_default();
        if !viewers.contains(&querier) {
            let admins: Vec<CanonicalAddr> = load(deps.storage, ADMINS_KEY)?;
            if !admins.contains(&querier) {
                return Err(StdError::generic_err("Not authorized"));
            }
        }
    }
    let common: CommonMetadata = may_load(deps.storage, METADATA_KEY)?.unwrap_or(CommonMetadata {
        public: None,
        private: None,
    });

    to_binary(&QueryAnswer::Metadata {
        public_metadata: common.public,
        private_metadata: common.private,
    })
}

/// Returns StdResult<CanonicalAddr> from determining the querying address
/// (if possible) either from a Permit or a ViewerInfo
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
) -> StdResult<CanonicalAddr> {
    if let Some(pmt) = permit {
        // Validate permit content
        let querier = validate(
            deps,
            PREFIX_REVOKED_PERMITS,
            &pmt,
            my_addr.to_string(),
            Some("secret"),
        )
        .and_then(|a| deps.api.addr_validate(&a))
        .and_then(|a| deps.api.addr_canonicalize(a.as_str()))?;
        if !pmt.check_permission(&secret_toolkit::permit::TokenPermissions::Owner) {
            return Err(StdError::generic_err(format!(
                "Owner permission is required for queries, got permissions {:?}",
                pmt.params.permissions
            )));
        }
        return Ok(querier);
    }
    if let Some(vwr) = viewer {
        let hmn = deps.api.addr_validate(&vwr.address)?;
        let raw = deps.api.addr_canonicalize(hmn.as_str())?;
        ViewingKey::check(deps.storage, hmn.as_str(), &vwr.viewing_key).map_err(|_| {
            StdError::generic_err("Wrong viewing key for this address or viewing key not set")
        })?;
        return Ok(raw);
    }
    Err(StdError::generic_err(
        "A permit or viewing key must be provided",
    ))
}

/// Returns StdResult<()> after verifying the querier is a Viewer
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - address and key making an authenticated query request
fn check_viewer(deps: Deps, viewer: ViewerInfo) -> StdResult<()> {
    let querier = get_querier(deps, Some(viewer), None, &Addr::unchecked("Not Used"))?;
    // only allow viewers to call this
    let viewers: Vec<CanonicalAddr> = may_load(deps.storage, VIEWERS_KEY)?.unwrap_or_default();
    if !viewers.contains(&querier) {
        return Err(StdError::generic_err("Not a viewer"));
    }
    Ok(())
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
    let address = get_querier(deps, viewer, permit, my_addr)?;
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

pub enum AddrType {
    Admin,
    Viewer,
    Minter,
}

/// Returns StdResult<Response>
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
fn try_process_auth_list(
    deps: DepsMut,
    sender: &Addr,
    update_list: &[String],
    is_add: bool,
    list: AddrType,
) -> StdResult<Response> {
    // only allow admins to do this
    let admins = check_admin_tx(deps.as_ref(), sender)?;

    // get the right authorization list info
    let (mut current_list, key) = match list {
        AddrType::Admin => (admins, ADMINS_KEY),
        AddrType::Viewer => (
            may_load::<Vec<CanonicalAddr>>(deps.storage, VIEWERS_KEY)?.unwrap_or_default(),
            VIEWERS_KEY,
        ),
        AddrType::Minter => (
            may_load::<Vec<CanonicalAddr>>(deps.storage, MINTERS_KEY)?.unwrap_or_default(),
            MINTERS_KEY,
        ),
    };
    // update the authorization list if needed
    let save_it = if is_add {
        add_addrs_to_auth(deps.api, &mut current_list, update_list)?
    } else {
        remove_addrs_from_auth(deps.api, &mut current_list, update_list)?
    };
    // save list if it changed
    if save_it {
        save(deps.storage, key, &current_list)?;
    }
    let new_list = current_list
        .iter()
        .map(|a| deps.api.addr_humanize(a))
        .collect::<StdResult<Vec<Addr>>>()?;
    let resp = match list {
        AddrType::Admin => ExecuteAnswer::AdminsList { admins: new_list },
        AddrType::Viewer => ExecuteAnswer::ViewersList { viewers: new_list },
        AddrType::Minter => ExecuteAnswer::MintersList { minters: new_list },
    };
    Ok(Response::new().set_data(to_binary(&resp)?))
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
fn add_variants(
    storage: &mut dyn Storage,
    cat_key: &[u8],
    variants: Vec<VariantInfo>,
    cat: &mut Category,
) -> StdResult<()> {
    for var in variants.into_iter() {
        let var_name_key = var.name.as_bytes();
        let mut var_map = PrefixedStorage::multilevel(storage, &[PREFIX_VARIANT_MAP, cat_key]);
        if may_load::<u8>(&var_map, var_name_key)?.is_some() {
            return Err(StdError::generic_err(format!(
                "Variant name:  {} already exists under category:  {}",
                &var.name, &cat.name
            )));
        }
        save(&mut var_map, var_name_key, &cat.cnt)?;
        let mut var_store = PrefixedStorage::multilevel(storage, &[PREFIX_VARIANT, cat_key]);
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

/// Returns StdResult<Response>
///
/// updates the dependencies list
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `sender` - a reference to the message sender
/// * `update_list` - list of dependencies to use for update
/// * `action` - Action to perform on the dependency list
fn try_process_dep_list(
    deps: DepsMut,
    sender: &Addr,
    update_list: &[Dependencies],
    action: Action,
) -> StdResult<Response> {
    // only allow admins to do this
    check_admin_tx(deps.as_ref(), sender)?;

    let mut depends: Vec<StoredDependencies> =
        may_load(deps.storage, DEPENDENCIES_KEY)?.unwrap_or_default();
    let mut save_dep = false;
    let status = "success".to_string();
    let resp = match action {
        Action::Add => {
            for dep in update_list.iter() {
                let stored = dep.to_stored(deps.storage)?;
                // add if this variant does not already have dependencies
                if !depends.iter().any(|d| d.id == stored.id) {
                    depends.push(stored);
                    save_dep = true;
                }
            }
            ExecuteAnswer::AddDependencies { status }
        }
        Action::Remove => {
            let old_len = depends.len();
            let rem_list = update_list
                .iter()
                .map(|d| d.to_stored(deps.storage))
                .collect::<StdResult<Vec<StoredDependencies>>>()?;
            depends.retain(|d| !rem_list.iter().any(|r| r.id == d.id));
            // only save if the list changed
            if old_len != depends.len() {
                save_dep = true;
            }
            ExecuteAnswer::RemoveDependencies { status }
        }
        Action::Modify => {
            for dep in update_list.iter() {
                let stored = dep.to_stored(deps.storage)?;
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
            ExecuteAnswer::ModifyDependencies { status }
        }
    };
    if save_dep {
        save(deps.storage, DEPENDENCIES_KEY, &depends)?;
    }

    Ok(Response::new().set_data(to_binary(&resp)?))
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
fn displ_variant(
    storage: &dyn Storage,
    id: &StoredLayerId,
    depends: &[StoredDependencies],
    svgs: bool,
) -> StdResult<VariantInfoPlus> {
    let var_store =
        ReadonlyPrefixedStorage::multilevel(storage, &[PREFIX_VARIANT, &id.category.to_le_bytes()]);
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
fn use_back_cache(map: &dyn Storage, id: &str, back_cache: &mut Vec<BackCache>) -> StdResult<u8> {
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
fn replace_layer(
    storage: &dyn Storage,
    image: &mut [u8],
    new_layer: &LayerId,
    dependencies: &[StoredDependencies],
    cat_cache: &mut Vec<BackCache>,
    var_caches: &mut [Vec<BackCache>],
) -> StdResult<()> {
    let cat_map = ReadonlyPrefixedStorage::new(storage, PREFIX_CATEGORY_MAP);
    // if processing a Skull variant
    if new_layer.category == "Skull" {
        let skull_idx = use_back_cache(&cat_map, "Skull", cat_cache)?;
        let skull_var_map = ReadonlyPrefixedStorage::multilevel(
            storage,
            &[PREFIX_VARIANT_MAP, &skull_idx.to_le_bytes()],
        );
        let skull_cache = var_caches
            .get_mut(skull_idx as usize)
            .ok_or_else(|| StdError::generic_err("Variant caches improperly initialized"))?;
        let new_skull_var_idx = use_back_cache(&skull_var_map, &new_layer.variant, skull_cache)?;
        // if the skull is changing color
        if image[skull_idx as usize] != new_skull_var_idx {
            let chin_idx = use_back_cache(&cat_map, "Jaw Type", cat_cache)?;
            let chin_var_map = ReadonlyPrefixedStorage::multilevel(
                storage,
                &[PREFIX_VARIANT_MAP, &chin_idx.to_le_bytes()],
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
            storage,
            &[PREFIX_VARIANT_MAP, &cat_idx.to_le_bytes()],
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
                        storage,
                        &[PREFIX_VARIANT_MAP, &dep.category.to_le_bytes()],
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

/// Returns StdResult<(StoredLayerId, StoredLayerId)>
///
/// which is the layer ids of cyclops and jawless
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
fn get_type_layers(storage: &dyn Storage) -> StdResult<(StoredLayerId, StoredLayerId)> {
    let cat_map = ReadonlyPrefixedStorage::new(storage, PREFIX_CATEGORY_MAP);
    let eye_type_idx: u8 = may_load(&cat_map, "Eye Type".as_bytes())?
        .ok_or_else(|| StdError::generic_err("Eye Type layer category not found"))?;
    let chin_idx: u8 = may_load(&cat_map, "Jaw Type".as_bytes())?
        .ok_or_else(|| StdError::generic_err("Jaw Type layer category not found"))?;
    let chin_var_map = ReadonlyPrefixedStorage::multilevel(
        storage,
        &[PREFIX_VARIANT_MAP, &chin_idx.to_le_bytes()],
    );
    let jawless_idx: u8 = may_load(&chin_var_map, "None".as_bytes())?.ok_or_else(|| {
        StdError::generic_err("Did not find expected None variant for Jaw Type layer category")
    })?;
    let et_var_map = ReadonlyPrefixedStorage::multilevel(
        storage,
        &[PREFIX_VARIANT_MAP, &eye_type_idx.to_le_bytes()],
    );
    let cyclops_idx: u8 =
        may_load(&et_var_map, "EyeType.Cyclops".as_bytes())?.ok_or_else(|| {
            StdError::generic_err(
                "Did not find expected EyeType.Cyclops variant for Eye Type layer category",
            )
        })?;

    Ok((
        StoredLayerId {
            category: eye_type_idx,
            variant: cyclops_idx,
        },
        StoredLayerId {
            category: chin_idx,
            variant: jawless_idx,
        },
    ))
}
