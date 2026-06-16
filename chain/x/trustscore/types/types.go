package types

// TrustScore represents the stored reputation score of a guardian node.
type TrustScore struct {
	GuardianAddress string `json:"guardian_address"`
	Score           uint32 `json:"score"` // Fixed-point value out of 1,000,000 (1000000 = 100.00%)
	TotalTasks      uint32 `json:"total_tasks"`
	SuccessfulTasks uint32 `json:"successful_tasks"`
	LastUpdated     int64  `json:"last_updated"`
}
