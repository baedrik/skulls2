use crate::contract::BLOCK_SIZE;
use crate::msg::{LayerId, ViewerInfo};
use secret_toolkit::utils::Query;
use serde::{Deserialize, Serialize};

/// the svg server's query messages
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerQueryMsg {
    /// display if a skull is a cyclops and if it is jawless
    SkullType {
        /// address and viewing key of this alchemy contract
        viewer: ViewerInfo,
        /// image indices
        image: Vec<u8>,
    },
    /// return the new image vec resulting from altering the specified layers
    Transmute {
        /// address and viewing key of this alchemy contract
        viewer: ViewerInfo,
        /// current image indices
        current: Vec<u8>,
        /// transmuted layers
        new_layers: Vec<LayerId>,
    },
}

impl Query for ServerQueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// info about the skull type
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SkullTypeResponse {
    /// true if the skull is a cyclops
    pub is_cyclops: bool,
    /// true if the skull is jawless
    pub is_jawless: bool,
}

/// wrapper to deserialize SkullType responses
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SkullTypeWrapper {
    pub skull_type: SkullTypeResponse,
}

/// display the new image vec after transmuted the requested layers
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TransmuteResponse {
    /// new image
    pub image: Vec<u8>,
}

/// wrapper to deserialize Transmute responses
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TransmuteWrapper {
    pub transmute: TransmuteResponse,
}
