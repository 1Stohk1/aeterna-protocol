package types

const (
	// ModuleName defines the module name
	ModuleName = "oracle"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// RouterKey defines the message routing key
	RouterKey = ModuleName
)

var (
	// PrefixTaskProof defines key prefix for storing TaskProof records: PrefixTaskProof + TaskId
	PrefixTaskProof = []byte{0x10}
)
