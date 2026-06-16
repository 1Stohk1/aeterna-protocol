package types

// AnchorCheckpoint represents a Bitcoin anchoring checkpoint record.
type AnchorCheckpoint struct {
	BtcTxHash   string `json:"btc_tx_hash"`
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	Creator     string `json:"creator"`
	EventName   string `json:"event_name"`
	Timestamp   int64  `json:"timestamp"`
}
