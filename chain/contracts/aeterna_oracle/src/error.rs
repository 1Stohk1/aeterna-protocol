use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized: sender does not hold a valid Soulbound Token (SBT)")]
    Unauthorized {},

    #[error("Invalid signature: Dilithium-5 signature verification failed")]
    InvalidSignature {},

    #[error("Stargate query failed: {0}")]
    StargateQueryFailed(String),

    #[error("Protobuf decode error: failed to decode response or payload: {0}")]
    ProtobufDecodeError(String),

    #[error("Task already submitted: task_id {0} has already been registered")]
    TaskAlreadySubmitted(String),
}
