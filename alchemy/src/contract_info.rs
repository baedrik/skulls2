use cosmwasm_std::{Api, CanonicalAddr, StdResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// code hash and address of a secret contract
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, JsonSchema)]
pub struct ContractInfo {
    /// contract's code hash string
    pub code_hash: String,
    /// contract's address
    pub address: String,
}

impl ContractInfo {
    /// Returns StdResult<StoreContractInfo> from creating a StoreContractInfo from a
    /// ContractInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn get_store(&self, api: &dyn Api) -> StdResult<StoreContractInfo> {
        Ok(StoreContractInfo {
            code_hash: self.code_hash.clone(),
            address: api
                .addr_validate(&self.address)
                .and_then(|a| api.addr_canonicalize(a.as_str()))?,
        })
    }

    /// Returns StdResult<StoreContractInfo> from converting a ContractInfo to a
    /// StoreContractInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn into_store(self, api: &dyn Api) -> StdResult<StoreContractInfo> {
        Ok(StoreContractInfo {
            code_hash: self.code_hash,
            address: api
                .addr_validate(&self.address)
                .and_then(|a| api.addr_canonicalize(a.as_str()))?,
        })
    }
}

/// code hash and address of a contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoreContractInfo {
    /// contract's code hash string
    pub code_hash: String,
    /// contract's address
    pub address: CanonicalAddr,
}

impl StoreContractInfo {
    /// Returns StdResult<ContractInfo> from creating a displayable ContractInfo from
    /// a StoreContractInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn get_humanized(&self, api: &dyn Api) -> StdResult<ContractInfo> {
        Ok(ContractInfo {
            code_hash: self.code_hash.clone(),
            address: api.addr_humanize(&self.address)?.into_string(),
        })
    }

    /// Returns StdResult<ContractInfo> from converting a StoreContractInfo to a
    /// displayable ContractInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn into_humanized(self, api: &dyn Api) -> StdResult<ContractInfo> {
        Ok(ContractInfo {
            code_hash: self.code_hash,
            address: api.addr_humanize(&self.address)?.into_string(),
        })
    }
}
