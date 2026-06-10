package types

const (
	// ModuleName defines the module name
	ModuleName = "trustscore"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName
)

var (
	// PrefixTrustScore defines key prefix for storing TrustScore records: PrefixTrustScore + Address
	PrefixTrustScore = []byte{0x20}
)
