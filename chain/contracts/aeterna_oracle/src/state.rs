use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub scale_factor: Uint128,
}

#[cw_serde]
pub struct TaskRecord {
    pub submitter: Addr,
    pub block_height: u64,
    pub manifest_hash: String,
    pub verified: bool,
}

#[cw_serde]
pub struct TrustMetrics {
    pub continuous_score: Uint128, // Scaled score (e.g. 950,000 equivalent to 0.95)
    pub total_submissions: u64,
    pub last_updated_height: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const BLOCKS: Map<&str, TaskRecord> = Map::new("blocks");
pub const TRUST_BOOK: Map<&Addr, TrustMetrics> = Map::new("trust_book");
