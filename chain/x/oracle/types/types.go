package types

// TaskProof represents the verified proof results of a genomic computation task.
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
}
