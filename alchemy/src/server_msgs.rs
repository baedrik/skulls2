use crate::contract::BLOCK_SIZE;
use crate::msg::{LayerId, StoredLayerId, VariantIdxName, ViewerInfo};
use secret_toolkit::utils::Query;
use serde::{Deserialize, Serialize};

/// the svg server's query messages
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerQueryMsg {
    /// return the new image vec resulting from altering the specified layers
    Transmute {
        /// address and viewing key of this alchemy contract
        viewer: ViewerInfo,
        /// current image indices
        current: Vec<u8>,
        /// transmuted layers
        new_layers: Vec<LayerId>,
    },
    /// display the StoredLayerId for jawless and cyclops, and the info about skull materials
    SkullTypePlus {
        /// address and viewing key of the alchemy contract
        viewer: ViewerInfo,
    },
}

impl Query for ServerQueryMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// info about the skull type
#[derive(Deserialize)]
pub struct SkullTypePlus {
    /// cyclops layer
    pub cyclops: StoredLayerId,
    /// jawless layer
    pub jawless: StoredLayerId,
    /// skull category index
    pub skull_idx: u8,
    /// list of all skull materials
    pub skull_variants: Vec<VariantIdxName>,
}

/// wrapper to deserialize SkullTypePlus responses
#[derive(Deserialize)]
pub struct SkullTypePlusWrapper {
    pub skull_type_plus: SkullTypePlus,
}

/// display the new image vec after transmuting the requested layers
#[derive(Deserialize)]
pub struct Transmute {
    /// new image
    pub image: Vec<u8>,
}

/// wrapper to deserialize Transmute responses
#[derive(Deserialize)]
pub struct TransmuteWrapper {
    pub transmute: Transmute,
}
