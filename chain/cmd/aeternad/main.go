package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/dilithium"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/config"
	tmlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/proxy"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
)

type SBT struct {
	GuardianAddress    string `json:"guardian_address"`
	TPMPubKey          string `json:"tpm_pubkey"`
	ManifestoHash      string `json:"manifesto_hash"`
	RegisteredAtHeight string `json:"registered_at_height"`
	Signature          string `json:"signature"`
}

type SubmitBlockPayload struct {
	GuardianAddress string `json:"guardian_address"`
	BlockHash       string `json:"block_hash"`
	BlockHeight     uint64 `json:"block_height"`
	TrustScore      string `json:"trust_score"`
	Signature       string `json:"signature"`
}

type TrustScore struct {
	GuardianAddress string `json:"guardian_address"`
	Score           uint32 `json:"score"`
	TotalTasks      uint32 `json:"total_tasks"`
	SuccessfulTasks uint32 `json:"successful_tasks"`
	LastUpdated     int64  `json:"last_updated"`
}

type TaskProof struct {
	TaskId          string `json:"task_id"`
	Creator         string `json:"creator"`
	ManifestHash    string `json:"manifest_hash"`
	GcContentCount  uint32 `json:"gc_content_count"`
	HammingDistance uint32 `json:"hamming_distance"`
	RefHash         string `json:"ref_hash"`
	ObsHash         string `json:"obs_hash"`
	Proof           []byte `json:"proof"`
	Verified        bool   `json:"verified"`
	Height          int64  `json:"height"`
	IpfsCid         string `json:"ipfs_cid,omitempty"`
}

type SubmitProofPayload struct {
	Creator         string      `json:"creator"`
	TaskId          string      `json:"task_id"`
	ManifestHash    string      `json:"manifest_hash"`
	GcContentCount  uint32      `json:"gc_content_count"`
	HammingDistance uint32      `json:"hamming_distance"`
	RefHash         string      `json:"ref_hash"`
	ObsHash         string      `json:"obs_hash"`
	Proof           interface{} `json:"proof"`
	IpfsCid         string      `json:"ipfs_cid,omitempty"`
	Signature       string      `json:"signature"`
}

type AnchorCheckpoint struct {
	BtcTxHash   string `json:"btc_tx_hash"`
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	Creator     string `json:"creator"`
	EventName   string `json:"event_name"`
	Timestamp   int64  `json:"timestamp"`
}

type SubmitAnchorPayload struct {
	Creator     string `json:"creator"`
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	BtcTxHash   string `json:"btc_tx_hash"`
	EventName   string `json:"event_name"`
	Signature   string `json:"signature"`
}

type NodeState struct {
	mu              sync.RWMutex
	startTime       time.Time
	startHeight     uint64
	latestBlockTime time.Time
	guardians       map[string]SBT
	trustScores     map[string]TrustScore // address -> TrustScore
	taskProofs      map[string]TaskProof  // task_id -> TaskProof
	latestAnchor    *AnchorCheckpoint
	moniker         string
	rpcAddr         string
	restAddr        string
}

func (s *NodeState) GetHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.startHeight
}

func (s *NodeState) GetBlockTime() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latestBlockTime.IsZero() {
		return s.startTime.UTC().Format(time.RFC3339)
	}
	return s.latestBlockTime.UTC().Format(time.RFC3339)
}

func (s *NodeState) HandleStatus(w http.ResponseWriter, r *http.Request) {
	height := s.GetHeight()
	blockTime := s.GetBlockTime()

	res := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      -1,
		"result": map[string]interface{}{
			"node_info": map[string]interface{}{
				"protocol_version": map[string]interface{}{
					"p2p":   "8",
					"block": "11",
					"app":   "0",
				},
				"id":          "aeterna_node_id_" + s.moniker,
				"listen_addr": s.rpcAddr,
				"network":     "aeterna-1",
				"version":     "v0.38.6",
				"channels":    "4020212526272829",
				"moniker":     s.moniker,
				"other": map[string]interface{}{
					"tx_index":    "on",
					"rpc_address": "tcp://" + s.rpcAddr,
				},
			},
			"sync_info": map[string]interface{}{
				"latest_block_hash":     "A1B2C3D4E5F67890",
				"latest_app_hash":       "F67890A1B2C3D4E5",
				"latest_block_height":   strconv.FormatUint(height, 10),
				"latest_block_time":     blockTime,
				"earliest_block_hash":   "0000000000000000",
				"earliest_app_hash":     "",
				"earliest_block_height": "1",
				"earliest_block_time":   s.startTime.UTC().Format(time.RFC3339),
				"catching_up":           false,
			},
			"validator_info": map[string]interface{}{
				"address": "B1C2D3E4",
				"pub_key": map[string]interface{}{
					"type":  "tendermint/PubKeyEd25519",
					"value": "dummy_validator_pubkey_" + s.moniker,
				},
				"voting_power": "100",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (s *NodeState) HandleGetSBT(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) > 0 {
			address = parts[len(parts)-1]
		}
	}

	s.mu.RLock()
	sbt, exists := s.guardians[address]
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "SBT not found for address"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"sbt": sbt,
	})
}

func (s *NodeState) HandleListSBT(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	
	list := make([]SBT, 0, len(s.guardians))
	for _, v := range s.guardians {
		list = append(list, v)
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"guardians": list,
	})
}

type TxType string

const (
	TxRegisterSBT  TxType = "register_sbt"
	TxSubmitBlock  TxType = "submit_block"
	TxSubmitProof  TxType = "submit_proof"
	TxSubmitAnchor TxType = "submit_anchor"
)

type Transaction struct {
	Type    TxType          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func broadcastTx(rpcAddr string, txType TxType, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	tx := Transaction{
		Type:    txType,
		Payload: payloadBytes,
	}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return err
	}

	targetAddr := rpcAddr
	if !strings.HasPrefix(targetAddr, "tcp://") && !strings.HasPrefix(targetAddr, "http://") {
		targetAddr = "http://" + targetAddr
	}
	cli, err := rpchttp.New(targetAddr, "/websocket")
	if err != nil {
		return err
	}

	ctx := context.Background()
	res, err := cli.BroadcastTxCommit(ctx, txBytes)
	if err != nil {
		return err
	}

	if res.CheckTx.Code != 0 {
		return fmt.Errorf("CheckTx failed: %s", res.CheckTx.Log)
	}
	if res.TxResult.Code != 0 {
		return fmt.Errorf("DeliverTx failed: %s", res.TxResult.Log)
	}

	return nil
}

func (s *NodeState) HandleRegisterSBT(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		GuardianAddress string `json:"guardian_address"`
		TPMPubKey       string `json:"tpm_pubkey"`
		ManifestoHash   string `json:"manifesto_hash"`
		Signature       string `json:"signature"`
	}

	w.Header().Set("Content-Type", "application/json")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read request body"})
		return
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to parse JSON"})
		return
	}

	if payload.GuardianAddress == "" || payload.TPMPubKey == "" || payload.ManifestoHash == "" || payload.Signature == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing required fields"})
		return
	}

	err = broadcastTx(s.rpcAddr, TxRegisterSBT, payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Transaction failed: %v", err)})
		return
	}

	s.mu.RLock()
	sbt := s.guardians[payload.GuardianAddress]
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"sbt":     sbt,
	})
}

func (s *NodeState) HandleSmartQuery(w http.ResponseWriter, r *http.Request) {
	queryB64 := r.PathValue("query_base64")
	if queryB64 == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) > 0 {
			queryB64 = parts[len(parts)-1]
		}
	}

	queryBytes, err := base64.StdEncoding.DecodeString(queryB64)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid base64 query"})
		return
	}

	log.Printf("[%s] Smart query: %s\n", s.moniker, string(queryBytes))

	var queryMap map[string]map[string]interface{}
	if err := json.Unmarshal(queryBytes, &queryMap); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid query JSON"})
		return
	}

	var score = "1.000000000000000000"
	if getTrustScore, exists := queryMap["get_trust_score"]; exists {
		if addr, ok := getTrustScore["address"].(string); ok {
			s.mu.RLock()
			if storedScore, ok := s.trustScores[addr]; ok {
				score = fmt.Sprintf("%.18f", float64(storedScore.Score)/1000000.0)
			}
			s.mu.RUnlock()
		}
	}

	res := map[string]interface{}{
		"data": map[string]string{
			"score": score,
		},
	}
	json.NewEncoder(w).Encode(res)
}

func (s *NodeState) HandleSubmitBlock(w http.ResponseWriter, r *http.Request) {
	var payload SubmitBlockPayload
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid payload JSON"})
		return
	}

	if payload.GuardianAddress == "" || payload.BlockHash == "" || payload.BlockHeight == 0 || payload.Signature == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing required fields"})
		return
	}

	s.mu.RLock()
	sbt, exists := s.guardians[payload.GuardianAddress]
	s.mu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "SBT not found for guardian"})
		return
	}

	if !strings.HasPrefix(sbt.TPMPubKey, "dummy_") {
		pubKeyBytes, err := hex.DecodeString(sbt.TPMPubKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to decode public key: %v", err)})
			return
		}

		sigBytes, err := hex.DecodeString(payload.Signature)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to decode signature: %v", err)})
			return
		}

		mode := dilithium.Mode5
		if len(pubKeyBytes) != mode.PublicKeySize() {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Dilithium-5 public key size"})
			return
		}
		pubKey := mode.PublicKeyFromBytes(pubKeyBytes)

		msgBytes := append([]byte(payload.BlockHash), []byte(strconv.FormatUint(payload.BlockHeight, 10))...)
		if !mode.Verify(pubKey, msgBytes, sigBytes) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Dilithium-5 signature"})
			return
		}
	} else {
		log.Printf("[%s] Bypassing Dilithium-5 verification because public key starts with 'dummy_'\n", s.moniker)
	}

	err = broadcastTx(s.rpcAddr, TxSubmitBlock, payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Transaction failed: %v", err)})
		return
	}

	s.mu.RLock()
	ts := s.trustScores[payload.GuardianAddress]
	s.mu.RUnlock()

	newScoreStr := fmt.Sprintf("%.18f", float64(ts.Score)/1000000.0)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"trust_score": newScoreStr,
	})
}

func decodeProof(proofRaw interface{}) ([]byte, error) {
	if proofRaw == nil {
		return nil, fmt.Errorf("proof is nil")
	}

	switch val := proofRaw.(type) {
	case string:
		bz, err := hex.DecodeString(val)
		if err == nil && len(bz) == 128 {
			return bz, nil
		}
		bz, err = base64.StdEncoding.DecodeString(val)
		if err == nil {
			return bz, nil
		}
		bz, err = base64.URLEncoding.DecodeString(val)
		if err == nil {
			return bz, nil
		}
		return nil, fmt.Errorf("failed to decode proof as hex or base64")

	case []interface{}:
		bz := make([]byte, len(val))
		for i, x := range val {
			f, ok := x.(float64)
			if !ok {
				return nil, fmt.Errorf("invalid byte type at index %d", i)
			}
			bz[i] = byte(f)
		}
		return bz, nil
	}

	return nil, fmt.Errorf("unsupported proof format type: %T", proofRaw)
}

func (s *NodeState) HandleSubmitProof(w http.ResponseWriter, r *http.Request) {
	var payload SubmitProofPayload
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid payload JSON"})
		return
	}

	if payload.Creator == "" || payload.TaskId == "" || payload.ManifestHash == "" || payload.RefHash == "" || payload.ObsHash == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing required fields"})
		return
	}

	proofBytes, err := decodeProof(payload.Proof)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Invalid proof format: %v", err)})
		return
	}

	if len(proofBytes) != 128 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("invalid zk-SNARK proof size: expected exactly 128 bytes, got %d", len(proofBytes)),
		})
		return
	}

	s.mu.RLock()
	sbt, exists := s.guardians[payload.Creator]
	s.mu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "SBT not found for creator"})
		return
	}

	if !strings.HasPrefix(sbt.TPMPubKey, "dummy_") {
		pubKeyBytes, err := hex.DecodeString(sbt.TPMPubKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to decode guardian public key: %v", err)})
			return
		}

		sigBytes, err := hex.DecodeString(payload.Signature)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to decode signature: %v", err)})
			return
		}

		mode := dilithium.Mode5
		if len(pubKeyBytes) != mode.PublicKeySize() {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Dilithium-5 public key size"})
			return
		}
		pubKey := mode.PublicKeyFromBytes(pubKeyBytes)

		msgBytes := append([]byte(payload.TaskId), []byte(payload.ManifestHash)...)
		if !mode.Verify(pubKey, msgBytes, sigBytes) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Dilithium-5 signature"})
			return
		}
	} else {
		log.Printf("[%s] Bypassing Dilithium-5 verification because public key starts with 'dummy_'\n", s.moniker)
	}

	s.mu.RLock()
	_, proofExists := s.taskProofs[payload.TaskId]
	s.mu.RUnlock()

	if proofExists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("task_id '%s' has already been submitted", payload.TaskId)})
		return
	}

	taskProof := TaskProof{
		TaskId:          payload.TaskId,
		Creator:         payload.Creator,
		ManifestHash:    payload.ManifestHash,
		GcContentCount:  payload.GcContentCount,
		HammingDistance: payload.HammingDistance,
		RefHash:         payload.RefHash,
		ObsHash:         payload.ObsHash,
		Proof:           proofBytes,
		Verified:        true,
		Height:          0,
		IpfsCid:         payload.IpfsCid,
	}

	err = broadcastTx(s.rpcAddr, TxSubmitProof, taskProof)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Transaction failed: %v", err)})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"verified": true,
	})
}

func (s *NodeState) HandleGetTrustScore(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) > 0 {
			address = parts[len(parts)-1]
		}
	}

	s.mu.RLock()
	ts, exists := s.trustScores[address]
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Trust score not found for address"})
		return
	}

	scoreStr := fmt.Sprintf("%.18f", float64(ts.Score)/1000000.0)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"score":            scoreStr,
		"total_tasks":      ts.TotalTasks,
		"successful_tasks": ts.SuccessfulTasks,
		"last_updated":     ts.LastUpdated,
	})
}

func (s *NodeState) HandleListProofs(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	list := make([]TaskProof, 0, len(s.taskProofs))
	for _, v := range s.taskProofs {
		list = append(list, v)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"proofs": list,
	})
}

func (s *NodeState) HandleSubmitAnchor(w http.ResponseWriter, r *http.Request) {
	var payload SubmitAnchorPayload
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read body"})
		return
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid payload JSON"})
		return
	}

	if payload.Creator == "" || payload.BlockHash == "" || payload.BlockHeight == 0 || payload.BtcTxHash == "" || payload.Signature == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing required fields"})
		return
	}

	s.mu.RLock()
	sbt, exists := s.guardians[payload.Creator]
	s.mu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "SBT not found for creator"})
		return
	}

	if !strings.HasPrefix(sbt.TPMPubKey, "dummy_") {
		pubKeyBytes, err := hex.DecodeString(sbt.TPMPubKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to decode guardian public key: %v", err)})
			return
		}

		sigBytes, err := hex.DecodeString(payload.Signature)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to decode signature: %v", err)})
			return
		}

		mode := dilithium.Mode5
		if len(pubKeyBytes) != mode.PublicKeySize() {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Dilithium-5 public key size"})
			return
		}
		pubKey := mode.PublicKeyFromBytes(pubKeyBytes)

		msgBytes := append([]byte(payload.Creator), []byte(payload.BlockHash)...)
		msgBytes = append(msgBytes, []byte(strconv.FormatUint(payload.BlockHeight, 10))...)
		msgBytes = append(msgBytes, []byte(payload.BtcTxHash)...)
		msgBytes = append(msgBytes, []byte(payload.EventName)...)

		if !mode.Verify(pubKey, msgBytes, sigBytes) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Dilithium-5 signature"})
			return
		}
	} else {
		log.Printf("[%s] Bypassing Dilithium-5 verification because public key starts with 'dummy_'\n", s.moniker)
	}

	err = broadcastTx(s.rpcAddr, TxSubmitAnchor, payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Transaction failed: %v", err)})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (s *NodeState) HandleGetLatestAnchor(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	latest := s.latestAnchor
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if latest == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "No anchor checkpoint submitted yet"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"latest_anchor": latest,
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, r)
	})
}

type AeternaABCIApp struct {
	abcitypes.BaseApplication
	state *NodeState
}

func (app *AeternaABCIApp) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	app.state.mu.Lock()
	defer app.state.mu.Unlock()

	app.state.startHeight = uint64(req.Height)
	app.state.latestBlockTime = req.Time

	var txResults []*abcitypes.ExecTxResult

	for _, txBytes := range req.Txs {
		var tx Transaction
		if err := json.Unmarshal(txBytes, &tx); err != nil {
			txResults = append(txResults, &abcitypes.ExecTxResult{
				Code: 1,
				Log:  fmt.Sprintf("failed to parse transaction: %v", err),
			})
			continue
		}

		var code uint32 = 0
		var logMsg string

		switch tx.Type {
		case TxRegisterSBT:
			var payload struct {
				GuardianAddress string `json:"guardian_address"`
				TPMPubKey       string `json:"tpm_pubkey"`
				ManifestoHash   string `json:"manifesto_hash"`
				Signature       string `json:"signature"`
			}
			if err := json.Unmarshal(tx.Payload, &payload); err != nil {
				code = 2
				logMsg = err.Error()
			} else {
				sbt := SBT{
					GuardianAddress:    payload.GuardianAddress,
					TPMPubKey:          payload.TPMPubKey,
					ManifestoHash:      payload.ManifestoHash,
					RegisteredAtHeight: strconv.FormatUint(uint64(req.Height), 10),
					Signature:          payload.Signature,
				}
				app.state.guardians[payload.GuardianAddress] = sbt
				if _, exists := app.state.trustScores[payload.GuardianAddress]; !exists {
					app.state.trustScores[payload.GuardianAddress] = TrustScore{
						GuardianAddress: payload.GuardianAddress,
						Score:           500000,
						TotalTasks:      0,
						SuccessfulTasks: 0,
						LastUpdated:     time.Now().Unix(),
					}
				}
				log.Printf("[%s] ABCI committed SBT for %s at height %d\n", app.state.moniker, payload.GuardianAddress, req.Height)
			}

		case TxSubmitBlock:
			var payload SubmitBlockPayload
			if err := json.Unmarshal(tx.Payload, &payload); err != nil {
				code = 3
				logMsg = err.Error()
			} else {
				if score, exists := app.state.trustScores[payload.GuardianAddress]; exists {
					score.TotalTasks++
					score.SuccessfulTasks++
					// Add 5% (50000 points) to the score, cap at 1,000,000 (100.00%)
					newScoreVal := score.Score + 50000
					if newScoreVal > 1000000 {
						newScoreVal = 1000000
					}
					score.Score = newScoreVal
					score.LastUpdated = time.Now().Unix()
					app.state.trustScores[payload.GuardianAddress] = score
				}
				log.Printf("[%s] ABCI committed block submission for %s\n", app.state.moniker, payload.GuardianAddress)
			}

		case TxSubmitProof:
			var payload TaskProof
			if err := json.Unmarshal(tx.Payload, &payload); err != nil {
				code = 4
				logMsg = err.Error()
			} else {
				payload.Height = req.Height
				payload.Verified = true
				app.state.taskProofs[payload.TaskId] = payload
				
				if score, exists := app.state.trustScores[payload.Creator]; exists {
					score.TotalTasks++
					score.SuccessfulTasks++
					newScoreVal := score.Score + 50000
					if newScoreVal > 1000000 {
						newScoreVal = 1000000
					}
					score.Score = newScoreVal
					score.LastUpdated = time.Now().Unix()
					app.state.trustScores[payload.Creator] = score
				}
				log.Printf("[%s] ABCI committed task proof for %s\n", app.state.moniker, payload.TaskId)
			}

		case TxSubmitAnchor:
			var payload SubmitAnchorPayload
			if err := json.Unmarshal(tx.Payload, &payload); err != nil {
				code = 5
				logMsg = err.Error()
			} else {
				checkpoint := AnchorCheckpoint{
					BtcTxHash:   payload.BtcTxHash,
					BlockHash:   payload.BlockHash,
					BlockHeight: payload.BlockHeight,
					Creator:     payload.Creator,
					EventName:   payload.EventName,
					Timestamp:   time.Now().Unix(),
				}
				app.state.latestAnchor = &checkpoint
				log.Printf("[%s] ABCI committed anchor checkpoint at height %d\n", app.state.moniker, payload.BlockHeight)
			}

		default:
			code = 6
			logMsg = "unknown transaction type"
		}

		txResults = append(txResults, &abcitypes.ExecTxResult{
			Code: code,
			Log:  logMsg,
		})
	}

	return &abcitypes.ResponseFinalizeBlock{
		TxResults: txResults,
	}, nil
}

func (app *AeternaABCIApp) Commit(ctx context.Context, req *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	return &abcitypes.ResponseCommit{}, nil
}

func (app *AeternaABCIApp) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	app.state.mu.RLock()
	defer app.state.mu.RUnlock()
	return &abcitypes.ResponseInfo{
		Version:          "1.0.0",
		AppVersion:       1,
		LastBlockHeight:  int64(app.state.startHeight),
		LastBlockAppHash: []byte(""),
	}, nil
}

func (app *AeternaABCIApp) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	return &abcitypes.ResponseInitChain{}, nil
}

func startCometBFTNode(homeDir string, rpcAddr string, p2pAddr string, peers string, abciApp abcitypes.Application) (*node.Node, error) {
	cfg := config.DefaultConfig()
	cfg.SetRoot(homeDir)
	
	if err := os.MkdirAll(filepath.Join(homeDir, "config"), 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(homeDir, "data"), 0755); err != nil {
		return nil, err
	}
	
	if !strings.HasPrefix(rpcAddr, "tcp://") {
		cfg.RPC.ListenAddress = "tcp://" + rpcAddr
	} else {
		cfg.RPC.ListenAddress = rpcAddr
	}

	if p2pAddr != "" {
		if !strings.HasPrefix(p2pAddr, "tcp://") {
			cfg.P2P.ListenAddress = "tcp://" + p2pAddr
		} else {
			cfg.P2P.ListenAddress = p2pAddr
		}
	}

	cfg.P2P.PersistentPeers = peers
	cfg.P2P.AddrBookStrict = false
	cfg.P2P.AllowDuplicateIP = true
	
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout))
	logger = tmlog.NewFilter(logger, tmlog.AllowInfo())
	
	pv := privval.LoadOrGenFilePV(cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile())
	nodeKey, err := p2p.LoadNodeKey(cfg.NodeKeyFile())
	if err != nil {
		nodeKey, err = p2p.LoadOrGenNodeKey(cfg.NodeKeyFile())
		if err != nil {
			return nil, err
		}
	}
	
	tmNode, err := node.NewNode(
		cfg,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(abciApp),
		node.DefaultGenesisDocProviderFunc(cfg),
		config.DefaultDBProvider,
		node.DefaultMetricsProvider(cfg.Instrumentation),
		logger,
	)
	if err != nil {
		return nil, err
	}
	
	err = tmNode.Start()
	return tmNode, err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: aeternad <command> [flags]")
		fmt.Println("Commands:")
		fmt.Println("  init          Initialize configuration and genesis")
		fmt.Println("  start         Start the AppChain consensus node")
		fmt.Println("  show-node-id  Show the node P2P ID")
		os.Exit(1)
	}

	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...) // shift args for flag package

	switch command {
	case "show-node-id":
		homeFlag := flag.String("home", "", "home directory path")
		flag.Parse()

		homeDir := *homeFlag
		if homeDir == "" {
			userHome, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("Failed to get user home: %v", err)
			}
			homeDir = filepath.Join(userHome, ".aeternad")
		}

		cfg := config.DefaultConfig()
		cfg.SetRoot(homeDir)
		nodeKey, err := p2p.LoadNodeKey(cfg.NodeKeyFile())
		if err != nil {
			log.Fatalf("Failed to load node key: %v", err)
		}
		fmt.Print(nodeKey.ID())
		os.Exit(0)
	case "init":
		monikerFlag := flag.String("moniker", "prometheus-node", "node moniker name")
		homeFlag := flag.String("home", "", "home directory path")
		flag.Parse()
		_ = monikerFlag

		homeDir := *homeFlag
		if homeDir == "" {
			userHome, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("Failed to get user home dir: %v", err)
			}
			homeDir = filepath.Join(userHome, ".aeternad")
		}

		configDir := filepath.Join(homeDir, "config")
		dataDir := filepath.Join(homeDir, "data")

		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("Failed to create config dir: %v", err)
		}
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			log.Fatalf("Failed to create data dir: %v", err)
		}

		// Generate private validator key and node key
		cfg := config.DefaultConfig()
		cfg.SetRoot(homeDir)
		_ = privval.LoadOrGenFilePV(cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile())
		_, _ = p2p.LoadOrGenNodeKey(cfg.NodeKeyFile())

		genesisPath := filepath.Join(configDir, "genesis.json")
		genesisContent := map[string]interface{}{
			"genesis_time":   time.Now().UTC().Format(time.RFC3339),
			"chain_id":       "aeterna-1",
			"initial_height": "1",
			"app_state": map[string]interface{}{
				"guardian": map[string]interface{}{
					"guardians": []interface{}{},
				},
			},
		}
		genesisBytes, _ := json.MarshalIndent(genesisContent, "", "  ")
		if err := os.WriteFile(genesisPath, genesisBytes, 0644); err != nil {
			log.Fatalf("Failed to write genesis.json: %v", err)
		}

		fmt.Println("Genesis file initialized successfully.")

	case "start":
		rpcAddr := flag.String("rpc-addr", "127.0.0.1:26657", "CometBFT RPC listen address")
		restAddr := flag.String("rest-addr", "127.0.0.1:1317", "Cosmos REST listen address")
		moniker := flag.String("moniker", "prometheus-node", "node moniker")
		homeFlag := flag.String("home", "", "home directory path")
		p2pAddr := flag.String("p2p-addr", "tcp://0.0.0.0:26656", "CometBFT P2P listen address")
		peers := flag.String("peers", "", "CometBFT persistent peers")
		flag.Parse()

		guardians := make(map[string]SBT)
		trustScores := make(map[string]TrustScore)
		taskProofs := make(map[string]TaskProof)

		homeDir := *homeFlag
		if homeDir == "" {
			userHome, err := os.UserHomeDir()
			if err == nil {
				homeDir = filepath.Join(userHome, ".aeternad")
			}
		}

		if homeDir != "" {
			genesisPath := filepath.Join(homeDir, "config", "genesis.json")
			if _, err := os.Stat(genesisPath); err == nil {
				log.Printf("Loading genesis from %s...\n", genesisPath)
				if genesisBytes, err := os.ReadFile(genesisPath); err == nil {
					var genesisMap map[string]interface{}
					if err := json.Unmarshal(genesisBytes, &genesisMap); err == nil {
						if appState, ok := genesisMap["app_state"].(map[string]interface{}); ok {
							if guardianState, ok := appState["guardian"].(map[string]interface{}); ok {
								if guardiansList, ok := guardianState["guardians"].([]interface{}); ok {
									for _, g := range guardiansList {
										if gMap, ok := g.(map[string]interface{}); ok {
											addr, _ := gMap["guardian_address"].(string)
											tpm, _ := gMap["tpm_pubkey"].(string)
											mHash, _ := gMap["manifesto_hash"].(string)
											regHeight, _ := gMap["registered_at_height"].(string)
											sig, _ := gMap["signature"].(string)
											if addr != "" {
												guardians[addr] = SBT{
													GuardianAddress:    addr,
													TPMPubKey:          tpm,
													ManifestoHash:      mHash,
													RegisteredAtHeight: regHeight,
													Signature:          sig,
												}
												trustScores[addr] = TrustScore{
													GuardianAddress: addr,
													Score:           500000,
													TotalTasks:      0,
													SuccessfulTasks: 0,
													LastUpdated:     time.Now().Unix(),
												}
												log.Printf("[%s] Loaded genesis SBT for guardian: %s\n", *moniker, addr)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		state := &NodeState{
			startTime:   time.Now(),
			startHeight: 0,
			guardians:   guardians,
			trustScores: trustScores,
			taskProofs:  taskProofs,
			moniker:     *moniker,
			rpcAddr:     *rpcAddr,
			restAddr:    *restAddr,
		}

		// Start CometBFT in-process node
		abciApp := &AeternaABCIApp{
			state: state,
		}
		tmNode, err := startCometBFTNode(homeDir, *rpcAddr, *p2pAddr, *peers, abciApp)
		if err != nil {
			log.Fatalf("Failed to start CometBFT node: %v", err)
		}
		defer func() {
			tmNode.Stop()
			tmNode.Wait()
		}()

		// Set up Cosmos SDK REST Server
		restMux := http.NewServeMux()
		restMux.HandleFunc("GET /status", state.HandleStatus)
		restMux.HandleFunc("GET /aeterna/guardian/v1/sbt/{address}", state.HandleGetSBT)
		restMux.HandleFunc("GET /aeterna/guardian/v1/sbt", state.HandleListSBT)
		restMux.HandleFunc("POST /aeterna/guardian/v1/register", state.HandleRegisterSBT)
		restMux.HandleFunc("GET /cosmwasm/wasm/v1/contract/{contract}/smart/{query_base64}", state.HandleSmartQuery)
		restMux.HandleFunc("POST /cosmwasm/wasm/v1/contract/{contract}/submit_block", state.HandleSubmitBlock)
		restMux.HandleFunc("POST /aeterna/oracle/v1/submit_proof", state.HandleSubmitProof)
		restMux.HandleFunc("GET /aeterna/trustscore/v1/score/{address}", state.HandleGetTrustScore)
		restMux.HandleFunc("GET /aeterna/oracle/v1/proof", state.HandleListProofs)
		restMux.HandleFunc("POST /aeterna/anchor/v1/submit", state.HandleSubmitAnchor)
		restMux.HandleFunc("GET /aeterna/anchor/v1/latest", state.HandleGetLatestAnchor)

		log.Printf("Starting aeternad console node [%s]...\n", *moniker)
		log.Printf("CometBFT RPC listening on: http://%s\n", *rpcAddr)
		log.Printf("Cosmos SDK REST listening on: http://%s\n", *restAddr)

		// Start REST server on main thread
		server := &http.Server{
			Addr:    *restAddr,
			Handler: corsMiddleware(restMux),
		}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("REST Server failed: %v", err)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}
