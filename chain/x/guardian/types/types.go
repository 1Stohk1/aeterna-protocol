package types

// GuardianSBT represents the stored Soulbound Token state for a node.
type GuardianSBT struct {
	SbtId              string `json:"sbt_id"`
	Owner              string `json:"owner"`
	DilithiumPubkey    []byte `json:"dilithium_pubkey"`
	ManifestoHash      string `json:"manifesto_hash"`
	TrustTier          uint32 `json:"trust_tier"`
	RegistrationHeight int64  `json:"registration_height"`
}
