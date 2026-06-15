package main

import (
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
}

type NodeState struct {
	mu           sync.RWMutex
	startTime    time.Time
	startHeight  uint64
	guardians    map[string]SBT
	trustScores  map[string]TrustScore // address -> TrustScore
	taskProofs   map[string]TaskProof  // task_id -> TaskProof
	moniker      string
	rpcAddr      string
	restAddr     string
}

func (s *NodeState) GetHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	elapsed := time.Since(s.startTime)
	blocks := uint64(elapsed.Seconds() / 6.0)
	return s.startHeight + blocks
}

func (s *NodeState) GetBlockTime() string {
	height := s.GetHeight()
	blockTime := s.startTime.Add(time.Duration(height) * 6 * time.Second)
	return blockTime.UTC().Format(time.RFC3339)
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
	
	// Convert map to slice to make it easy to loop over
	list := make([]SBT, 0, len(s.guardians))
	for _, v := range s.guardians {
		list = append(list, v)
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"guardians": list,
	})
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

	height := s.GetHeight()
	sbt := SBT{
		GuardianAddress:    payload.GuardianAddress,
		TPMPubKey:          payload.TPMPubKey,
		ManifestoHash:      payload.ManifestoHash,
		RegisteredAtHeight: strconv.FormatUint(height, 10),
		Signature:          payload.Signature,
	}

	s.mu.Lock()
	s.guardians[payload.GuardianAddress] = sbt
	if _, exists := s.trustScores[payload.GuardianAddress]; !exists {
		s.trustScores[payload.GuardianAddress] = TrustScore{
			GuardianAddress: payload.GuardianAddress,
			Score:           500000,
			TotalTasks:      0,
			SuccessfulTasks: 0,
			LastUpdated:     time.Now().Unix(),
		}
	}
	s.mu.Unlock()

	log.Printf("[%s] Registered SBT for guardian address %s at height %d\n", s.moniker, payload.GuardianAddress, height)

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

	var score = "1.000000000000000000" // default score if address not registered or score not found
	if getTrustScore, exists := queryMap["get_trust_score"]; exists {
		if addr, ok := getTrustScore["address"].(string); ok {
			s.mu.RLock()
			if storedScore, ok := s.trustScores[addr]; ok {
				scoreVal := float64(storedScore.Score) / 1000000.0
				score = fmt.Sprintf("%.18f", scoreVal)
			}
			s.mu.RUnlock()
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"score": score,
		},
	})
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

	if payload.GuardianAddress == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing guardian_address field"})
		return
	}

	s.mu.Lock()
	ts, exists := s.trustScores[payload.GuardianAddress]
	if !exists {
		ts = TrustScore{
			GuardianAddress: payload.GuardianAddress,
			Score:           500000,
			TotalTasks:      0,
			SuccessfulTasks: 0,
		}
	}

	ts.TotalTasks++
	ts.SuccessfulTasks++
	// Add 5% (50000 points) to the score, cap at 1,000,000 (100.00%)
	newScoreVal := ts.Score + 50000
	if newScoreVal > 1000000 {
		newScoreVal = 1000000
	}
	ts.Score = newScoreVal
	ts.LastUpdated = time.Now().Unix()
	s.trustScores[payload.GuardianAddress] = ts
	s.mu.Unlock()

	newScoreStr := fmt.Sprintf("%.18f", float64(newScoreVal)/1000000.0)
	log.Printf("[%s] Block submitted by %s. Trust score updated to %s\n", s.moniker, payload.GuardianAddress, newScoreStr)

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
		// Attempt Hex decoding
		bz, err := hex.DecodeString(val)
		if err == nil && len(bz) == 128 {
			return bz, nil
		}
		// Attempt Base64 decoding
		bz, err = base64.StdEncoding.DecodeString(val)
		if err == nil {
			return bz, nil
		}
		// Try URL-safe Base64
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

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.taskProofs[payload.TaskId]; exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("task_id '%s' has already been submitted", payload.TaskId)})
		return
	}

	height := int64(s.startHeight + uint64(time.Since(s.startTime).Seconds()/6.0))
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
		Height:          height,
		IpfsCid:         payload.IpfsCid,
	}
	s.taskProofs[payload.TaskId] = taskProof

	ts, exists := s.trustScores[payload.Creator]
	if !exists {
		ts = TrustScore{
			GuardianAddress: payload.Creator,
			Score:           500000,
			TotalTasks:      0,
			SuccessfulTasks: 0,
		}
	}

	ts.TotalTasks++
	ts.SuccessfulTasks++
	ts.Score = uint32((uint64(ts.SuccessfulTasks) * 1000000) / uint64(ts.TotalTasks))
	ts.LastUpdated = time.Now().Unix()
	s.trustScores[payload.Creator] = ts

	log.Printf("[%s] Proof submitted successfully for task %s by %s. Trust score: %d/1000000\n",
		s.moniker, payload.TaskId, payload.Creator, ts.Score)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"verified": true,
		"success":  true,
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

	json.NewEncoder(w).Encode(map[string]interface{}{
		"trust_score": ts,
	})
}

func (s *NodeState) HandleListProofs(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	list := make([]TaskProof, 0, len(s.taskProofs))
	for _, p := range s.taskProofs {
		list = append(list, p)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"proofs": list,
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleInit(homeDir string, moniker string) {
	fmt.Printf("Initializing aeternad home directory at %s for moniker %s...\n", homeDir, moniker)

	configDir := filepath.Join(homeDir, "config")
	dataDir := filepath.Join(homeDir, "data")

	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Fatalf("Failed to create config dir: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data dir: %v", err)
	}

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
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: aeternad <command> [flags]")
		fmt.Println("Commands:")
		fmt.Println("  init   Initialize configuration and genesis")
		fmt.Println("  start  Start the AppChain emulator node")
		os.Exit(1)
	}

	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...) // shift args for flag package

	switch command {
	case "init":
		monikerFlag := flag.String("moniker", "prometheus-node", "node moniker name")
		homeFlag := flag.String("home", "", "home directory path")
		flag.Parse()

		homeDir := *homeFlag
		if homeDir == "" {
			userHome, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("Failed to get user home dir: %v", err)
			}
			homeDir = filepath.Join(userHome, ".aeternad")
		}

		handleInit(homeDir, *monikerFlag)

	case "start":
		rpcAddr := flag.String("rpc-addr", "127.0.0.1:26657", "CometBFT RPC listen address")
		restAddr := flag.String("rest-addr", "127.0.0.1:1317", "Cosmos REST listen address")
		moniker := flag.String("moniker", "prometheus-node", "node moniker")
		homeFlag := flag.String("home", "", "home directory path")
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
			startHeight: 1,
			guardians:   guardians,
			trustScores: trustScores,
			taskProofs:  taskProofs,
			moniker:     *moniker,
			rpcAddr:     *rpcAddr,
			restAddr:    *restAddr,
		}

		// Set up CometBFT RPC Server (e.g. status endpoint)
		rpcMux := http.NewServeMux()
		rpcMux.HandleFunc("GET /status", state.HandleStatus)
		rpcMux.HandleFunc("POST /status", state.HandleStatus)
		rpcMux.HandleFunc("GET /", state.HandleStatus)
		rpcMux.HandleFunc("POST /", state.HandleStatus) // Handles raw JSON-RPC status calls

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

		log.Printf("Starting aeternad emulator [%s]...\n", *moniker)
		log.Printf("CometBFT RPC listening on: http://%s\n", *rpcAddr)
		log.Printf("Cosmos SDK REST listening on: http://%s\n", *restAddr)

		// Start RPC server in background
		go func() {
			server := &http.Server{
				Addr:    *rpcAddr,
				Handler: corsMiddleware(rpcMux),
			}
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("RPC Server failed: %v", err)
			}
		}()

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
