use cosmwasm_std::{Binary, QueryRequest, StdResult};
use prost::Message;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryGuardianSbtRequest {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryGuardianSbtResponse {
    #[prost(string, tag = "1")]
    pub sbt_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub owner: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "3")]
    pub dilithium_pubkey: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "4")]
    pub manifesto_hash: ::prost::alloc::string::String,
    #[prost(uint32, tag = "5")]
    pub trust_tier: u32,
    #[prost(int64, tag = "6")]
    pub registration_height: i64,
}

/// Helper to pack native Go query into a CosmWasm Stargate QueryRequest
pub fn query_guardian_sbt(address: String) -> StdResult<QueryRequest<cosmwasm_std::Empty>> {
    let proto_msg = QueryGuardianSbtRequest { address };
    let mut buf = Vec::new();
    proto_msg.encode(&mut buf).map_err(|e| {
        cosmwasm_std::StdError::generic_err(format!("Protobuf encoding error: {}", e))
    })?;

    Ok(QueryRequest::Stargate {
        path: "/aeterna.guardian.v1.Query/GuardianSBT".to_string(),
        data: Binary::from(buf),
    })
}
