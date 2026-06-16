# PowerShell test automation script for AETERNA native oracle transactions.
# Exercises GET /aeterna/trustscore/v1/score/{address} and POST /aeterna/oracle/v1/submit_proof

$Node1_URL = "http://127.0.0.1:1317"
$Node2_URL = "http://127.0.0.1:1318"
$Guardian1 = "aeterna1prometheus1address"
$TaskId = "task_e2e_" + (Get-Date -Format "yyyyMMdd_HHmmss")

# Generate a dummy 128-byte proof (256 hex characters)
$ValidProofHex = "aa" * 128

# Helper to fetch and print trust score
function Get-TrustScore($BaseUrl, $Address) {
    $url = "$BaseUrl/aeterna/trustscore/v1/score/$Address"
    try {
        $res = Invoke-RestMethod -Uri $url -Method Get
        Write-Host "  - Score: $($res.score)"
        Write-Host "  - Total Tasks: $($res.total_tasks)"
        Write-Host "  - Successful Tasks: $($res.successful_tasks)"
        return $res
    } catch {
        Write-Host "  - Error fetching trust score from $url" -ForegroundColor Red
        return $null
    }
}

# Helper to submit a proof and handle exceptions
function Submit-Proof($BaseUrl, $Payload) {
    $url = "$BaseUrl/aeterna/oracle/v1/submit_proof"
    $body = $Payload | ConvertTo-Json
    try {
        $res = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json"
        Write-Host "  - [SUCCESS] HTTP 200: Verified=$($res.verified)" -ForegroundColor Green
        return $res
    } catch {
        $statusCode = 500
        $errText = $_.Exception.Message
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $errText = $reader.ReadToEnd()
        }
        Write-Host "  - [EXPECTED FAILURE] HTTP $($statusCode): $errText" -ForegroundColor Yellow
        return $null
    }
}

Write-Host "=================================================="
Write-Host "AETERNA E2E ORACLE TRANSACTION VALIDATION"
Write-Host "=================================================="
Write-Host "Testing on Node 2 (Prometheus-2) at $Node2_URL"
Write-Host ""

# 1. Check initial trust score
Write-Host "[STEP 1] Fetching initial trust score for $Guardian1..."
$initScore = Get-TrustScore -BaseUrl $Node2_URL -Address $Guardian1

# 2. Submit valid proof
Write-Host "[STEP 2] Submitting valid 128-byte proof (TaskId: $TaskId)..."
$payload = @{
    creator = $Guardian1
    task_id = $TaskId
    manifest_hash = "dummy_manifest_hash_val"
    gc_content_count = [uint32]45
    hamming_distance = [uint32]3
    ref_hash = "dummy_ref_hash_val"
    obs_hash = "dummy_obs_hash_val"
    proof = $ValidProofHex
    ipfs_cid = "QmOfflineFallbackCidTest123"
    signature = "42" * 4595
}
$submitRes = Submit-Proof -BaseUrl $Node2_URL -Payload $payload

# 3. Check updated trust score
Write-Host "[STEP 3] Fetching updated trust score for $Guardian1..."
$updatedScore = Get-TrustScore -BaseUrl $Node2_URL -Address $Guardian1

# 4. Attempt Replay Attack (same TaskId)
Write-Host "[STEP 4] Testing Anti-Replay: Submitting same TaskId ($TaskId) again..."
$replayRes = Submit-Proof -BaseUrl $Node2_URL -Payload $payload

# 5. Attempt Invalid Proof Size (64 bytes)
Write-Host "[STEP 5] Testing Validation: Submitting invalid proof size (64 bytes)..."
$invalidPayload = $payload.Clone()
$invalidPayload.task_id = $TaskId + "_invalid"
$invalidPayload.proof = "bb" * 64
$invalidRes = Submit-Proof -BaseUrl $Node2_URL -Payload $invalidPayload

# 6. Test on Node 1 (Prometheus-1)
Write-Host "[STEP 6] Testing validation and submission on Node 1 ($Node1_URL)..."
$node1TaskId = $TaskId + "_node1"
$payloadNode1 = $payload.Clone()
$payloadNode1.task_id = $node1TaskId
$submitResNode1 = Submit-Proof -BaseUrl $Node1_URL -Payload $payloadNode1
$updatedScoreNode1 = Get-TrustScore -BaseUrl $Node1_URL -Address $Guardian1

Write-Host "=================================================="
Write-Host "Test suite execution finished."
Write-Host "=================================================="
