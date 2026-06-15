#!/bin/bash
# Bash script to test AETERNA native oracle transactions.
# Exercises GET /aeterna/trustscore/v1/score/{address} and POST /aeterna/oracle/v1/submit_proof

NODE1_URL="http://127.0.0.1:1317"
NODE2_URL="http://127.0.0.1:1318"
GUARDIAN="aeterna1prometheus1address"
TASK_ID="task_e2e_bash_$(date +%s)"
VALID_PROOF=$(printf 'a%.0s' {1..256}) # 256 characters = 128 bytes in hex

echo "=================================================="
echo "AETERNA E2E ORACLE BASH VALIDATION"
echo "=================================================="

echo "[STEP 1] Fetching initial score from Node 2..."
curl -s "$NODE2_URL/aeterna/trustscore/v1/score/$GUARDIAN"
echo -e "\n"

echo "[STEP 2] Submitting valid 128-byte proof..."
curl -i -X POST -H "Content-Type: application/json" -d "{
  \"creator\": \"$GUARDIAN\",
  \"task_id\": \"$TASK_ID\",
  \"manifest_hash\": \"dummy_manifest_hash_val\",
  \"gc_content_count\": 45,
  \"hamming_distance\": 3,
  \"ref_hash\": \"dummy_ref_hash_val\",
  \"obs_hash\": \"dummy_obs_hash_val\",
  \"proof\": \"$VALID_PROOF\"
}" "$NODE2_URL/aeterna/oracle/v1/submit_proof"
echo -e "\n"

echo "[STEP 3] Fetching updated score from Node 2..."
curl -s "$NODE2_URL/aeterna/trustscore/v1/score/$GUARDIAN"
echo -e "\n"

echo "[STEP 4] Testing anti-replay (same task_id)..."
curl -i -X POST -H "Content-Type: application/json" -d "{
  \"creator\": \"$GUARDIAN\",
  \"task_id\": \"$TASK_ID\",
  \"manifest_hash\": \"dummy_manifest_hash_val\",
  \"gc_content_count\": 45,
  \"hamming_distance\": 3,
  \"ref_hash\": \"dummy_ref_hash_val\",
  \"obs_hash\": \"dummy_obs_hash_val\",
  \"proof\": \"$VALID_PROOF\"
}" "$NODE2_URL/aeterna/oracle/v1/submit_proof"
echo -e "\n"

echo "[STEP 5] Testing invalid size (64 bytes)..."
INVALID_PROOF=$(printf 'b%.0s' {1..128})
curl -i -X POST -H "Content-Type: application/json" -d "{
  \"creator\": \"$GUARDIAN\",
  \"task_id\": \"${TASK_ID}_invalid\",
  \"manifest_hash\": \"dummy_manifest_hash_val\",
  \"gc_content_count\": 45,
  \"hamming_distance\": 3,
  \"ref_hash\": \"dummy_ref_hash_val\",
  \"obs_hash\": \"dummy_obs_hash_val\",
  \"proof\": \"$INVALID_PROOF\"
}" "$NODE2_URL/aeterna/oracle/v1/submit_proof"
echo -e "\n"

echo "[STEP 6] Submitting on Node 1..."
curl -i -X POST -H "Content-Type: application/json" -d "{
  \"creator\": \"$GUARDIAN\",
  \"task_id\": \"${TASK_ID}_node1\",
  \"manifest_hash\": \"dummy_manifest_hash_val\",
  \"gc_content_count\": 45,
  \"hamming_distance\": 3,
  \"ref_hash\": \"dummy_ref_hash_val\",
  \"obs_hash\": \"dummy_obs_hash_val\",
  \"proof\": \"$VALID_PROOF\"
}" "$NODE1_URL/aeterna/oracle/v1/submit_proof"
echo -e "\n"

echo "[STEP 7] Fetching updated score from Node 1..."
curl -s "$NODE1_URL/aeterna/trustscore/v1/score/$GUARDIAN"
echo -e "\n"

echo "=================================================="
echo "Test suite execution finished."
echo "=================================================="
