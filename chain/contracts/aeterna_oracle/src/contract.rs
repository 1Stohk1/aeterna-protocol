use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, Uint128,
};
use prost::Message;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, GetBlockResponse, GetTrustScoreResponse, InstantiateMsg, QueryMsg};
use crate::pqc::verify_dilithium5;
use crate::state::{Config, TaskRecord, TrustMetrics, BLOCKS, CONFIG, TRUST_BOOK};
use crate::stargate::{query_guardian_sbt, QueryGuardianSbtResponse};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let admin = deps.api.addr_validate(&msg.admin)?;
    let config = Config {
        admin,
        scale_factor: msg.initial_scale_factor,
    };
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SubmitBlock {
            block_height,
            task_id,
            computation_manifest_hash,
            operator_signature,
        } => execute_submit_block(
            deps,
            info,
            block_height,
            task_id,
            computation_manifest_hash,
            operator_signature,
        ),
    }
}

pub fn execute_submit_block(
    deps: DepsMut,
    info: MessageInfo,
    block_height: u64,
    task_id: String,
    computation_manifest_hash: String,
    operator_signature: Binary,
) -> Result<Response, ContractError> {
    // 1. Check if the task was already processed to prevent duplicate submissions
    if BLOCKS.has(deps.storage, &task_id) {
        return Err(ContractError::TaskAlreadySubmitted(task_id));
    }

    // 2. Prepare Stargate query to look up the sender's SBT in the Go x/guardian module
    let request = query_guardian_sbt(info.sender.to_string())?;

    // 3. Dispatch the query
    let response_bytes: Binary = deps.querier.query(&request).map_err(|e| {
        ContractError::StargateQueryFailed(e.to_string())
    })?;

    // 4. Decode response bytes using Prost
    let sbt_res = QueryGuardianSbtResponse::decode(response_bytes.as_slice()).map_err(|e| {
        ContractError::ProtobufDecodeError(e.to_string())
    })?;

    // 5. Ensure the sender has a valid SBT with a non-empty public key
    if sbt_res.dilithium_pubkey.is_empty() {
        return Err(ContractError::Unauthorized {});
    }

    // 6. Verify Dilithium-5 Signature over msg = task_id + computation_manifest_hash
    let mut msg_to_verify = Vec::new();
    msg_to_verify.extend_from_slice(task_id.as_bytes());
    msg_to_verify.extend_from_slice(computation_manifest_hash.as_bytes());

    verify_dilithium5(&sbt_res.dilithium_pubkey, &msg_to_verify, &operator_signature)?;

    // 7. Update Trust Score via fixed-point logic and save task execution record
    let config = CONFIG.load(deps.storage)?;
    let mut metrics = TRUST_BOOK
        .may_load(deps.storage, &info.sender)?
        .unwrap_or(TrustMetrics {
            continuous_score: Uint128::zero(),
            total_submissions: 0,
            last_updated_height: 0,
        });

    metrics.total_submissions += 1;
    metrics.last_updated_height = block_height;

    // Fixed-point delta: scale_factor / 100 * tier (e.g. tier 1 adds 10,000; tier 3 adds 30,000 for scale_factor = 1,000,000)
    let tier_multiplier = Uint128::from(sbt_res.trust_tier.max(1));
    let base_increment = config.scale_factor
        .checked_div(Uint128::from(100u128))
        .map_err(|e| ContractError::Std(StdError::generic_err(e.to_string())))?;
    let delta = base_increment
        .checked_mul(tier_multiplier)
        .map_err(|e| ContractError::Std(StdError::generic_err(e.to_string())))?;

    metrics.continuous_score = metrics.continuous_score
        .checked_add(delta)
        .map_err(|e| ContractError::Std(StdError::generic_err(e.to_string())))?;

    // Cap the Trust Score at the configured scale factor (representing 100% trust)
    if metrics.continuous_score > config.scale_factor {
        metrics.continuous_score = config.scale_factor;
    }

    // Save records
    let record = TaskRecord {
        submitter: info.sender.clone(),
        block_height,
        manifest_hash: computation_manifest_hash.clone(),
        verified: true,
    };
    BLOCKS.save(deps.storage, &task_id, &record)?;
    TRUST_BOOK.save(deps.storage, &info.sender, &metrics)?;

    Ok(Response::new()
        .add_attribute("action", "submit_block")
        .add_attribute("task_id", task_id)
        .add_attribute("guardian", info.sender.to_string())
        .add_attribute("continuous_score", metrics.continuous_score.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetBlock { task_id } => {
            let record = BLOCKS.load(deps.storage, &task_id)?;
            let response = GetBlockResponse {
                submitter: record.submitter.to_string(),
                block_height: record.block_height,
                manifest_hash: record.manifest_hash,
                verified: record.verified,
            };
            to_json_binary(&response)
        }
        QueryMsg::GetTrustScore { address } => {
            let addr = deps.api.addr_validate(&address)?;
            let metrics = TRUST_BOOK
                .may_load(deps.storage, &addr)?
                .unwrap_or(TrustMetrics {
                    continuous_score: Uint128::zero(),
                    total_submissions: 0,
                    last_updated_height: 0,
                });
            let response = GetTrustScoreResponse {
                continuous_score: metrics.continuous_score,
                total_submissions: metrics.total_submissions,
                last_updated_height: metrics.last_updated_height,
            };
            to_json_binary(&response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_env, mock_info, MockApi, MockStorage, MockQuerier};
    use cosmwasm_std::{
        from_json, Binary, ContractResult, Empty, OwnedDeps, Querier, QuerierResult, QueryRequest,
        SystemResult,
    };
    use std::marker::PhantomData;

    use crate::stargate::QueryGuardianSbtRequest;

    pub struct MyMockQuerier {
        pub base: MockQuerier,
        pub pk: Vec<u8>,
    }

    impl Querier for MyMockQuerier {
        fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
            let request: QueryRequest<Empty> = match from_json(bin_request) {
                Ok(req) => req,
                Err(e) => {
                    return SystemResult::Err(cosmwasm_std::SystemError::InvalidRequest {
                        error: e.to_string(),
                        request: Binary::from(bin_request),
                    })
                }
            };

            match request {
                QueryRequest::Stargate { path, data } => {
                    if path == "/aeterna.guardian.v1.Query/GuardianSBT" {
                        // Decode request using prost
                        let req = QueryGuardianSbtRequest::decode(data.as_slice()).unwrap();

                        // Encode response using prost
                        let res = QueryGuardianSbtResponse {
                            sbt_id: "SBT-Attestation-42".to_string(),
                            owner: req.address,
                            dilithium_pubkey: self.pk.clone(),
                            manifesto_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                            trust_tier: 2,
                            registration_height: 12345,
                        };
                        let mut buf = Vec::new();
                        res.encode(&mut buf).unwrap();

                        SystemResult::Ok(ContractResult::Ok(to_json_binary(&Binary::from(buf)).unwrap()))
                    } else {
                        SystemResult::Err(cosmwasm_std::SystemError::UnsupportedRequest {
                            kind: path,
                        })
                    }
                }
                _ => self.base.raw_query(bin_request),
            }
        }
    }

    fn mock_deps_with_pubkey(pk: Vec<u8>) -> OwnedDeps<MockStorage, MockApi, MyMockQuerier> {
        OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default(),
            querier: MyMockQuerier {
                base: MockQuerier::new(&[]),
                pk,
            },
            custom_query_type: PhantomData,
        }
    }

    #[test]
    fn test_instantiate_and_query() {
        let mut deps = mock_deps_with_pubkey(vec![]);

        let admin_addr = deps.api.addr_make("admin").to_string();
        let msg = InstantiateMsg {
            admin: admin_addr.clone(),
            initial_scale_factor: Uint128::from(1_000_000u128), // 1.0
        };
        let info = mock_info("creator", &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes[0].value, "instantiate");

        // Query default stats
        let guardian_addr = deps.api.addr_make("guardian").to_string();
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetTrustScore {
                address: guardian_addr,
            },
        )
        .unwrap();
        let stats: GetTrustScoreResponse = from_json(&query_res).unwrap();
        assert_eq!(stats.continuous_score, Uint128::zero());
        assert_eq!(stats.total_submissions, 0);
    }

    #[test]
    fn test_submit_block() {
        // 1. Generate Dilithium-5 Keypair
        let keypair = crystals_dilithium::dilithium5::Keypair::generate(None).unwrap();
        let pk = keypair.public.to_bytes().to_vec();

        let mut deps = mock_deps_with_pubkey(pk);

        // 2. Instantiate
        let admin_addr = deps.api.addr_make("admin").to_string();
        let inst_msg = InstantiateMsg {
            admin: admin_addr,
            initial_scale_factor: Uint128::from(1_000_000u128), // 1.0
        };
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("creator", &[]),
            inst_msg,
        )
        .unwrap();

        // 3. Create SubmitBlock message and operator signature over: task_id + manifest_hash
        let task_id = "task-alpha-123".to_string();
        let computation_manifest_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();

        let mut msg_to_sign = Vec::new();
        msg_to_sign.extend_from_slice(task_id.as_bytes());
        msg_to_sign.extend_from_slice(computation_manifest_hash.as_bytes());

        let signature = keypair.sign(&msg_to_sign).to_vec();

        let execute_msg = ExecuteMsg::SubmitBlock {
            block_height: 500,
            task_id: task_id.clone(),
            computation_manifest_hash: computation_manifest_hash.clone(),
            operator_signature: Binary::from(signature),
        };

        // 4. Execute SubmitBlock
        let guardian_addr = deps.api.addr_make("guardian");
        let info = mock_info(guardian_addr.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, execute_msg).unwrap();
        assert_eq!(res.attributes[0].value, "submit_block");
        assert_eq!(res.attributes[1].value, task_id.as_str());

        // 5. Verify score increment (scale_factor / 100 * tier = 1_000_000 / 100 * 2 = 20_000)
        assert_eq!(res.attributes[3].value, "20000");

        // 6. Query updated metrics
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetTrustScore {
                address: guardian_addr.to_string(),
            },
        )
        .unwrap();
        let metrics: GetTrustScoreResponse = from_json(&query_res).unwrap();
        assert_eq!(metrics.continuous_score, Uint128::from(20_000u128));
        assert_eq!(metrics.total_submissions, 1);
        assert_eq!(metrics.last_updated_height, 500);

        // 7. Query updated block details
        let query_block_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetBlock {
                task_id: task_id.clone(),
            },
        )
        .unwrap();
        let block_details: GetBlockResponse = from_json(&query_block_res).unwrap();
        assert_eq!(block_details.submitter, guardian_addr.to_string());
        assert_eq!(block_details.block_height, 500);
        assert_eq!(block_details.manifest_hash, computation_manifest_hash);
        assert!(block_details.verified);

        // 8. Try to submit the same task again and ensure it fails (prevent double submission)
        let dup_execute_msg = ExecuteMsg::SubmitBlock {
            block_height: 501,
            task_id: task_id.clone(),
            computation_manifest_hash,
            operator_signature: Binary::from(vec![]),
        };
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(guardian_addr.as_str(), &[]),
            dup_execute_msg,
        )
        .unwrap_err();
        assert_eq!(err, ContractError::TaskAlreadySubmitted(task_id));
    }
}
