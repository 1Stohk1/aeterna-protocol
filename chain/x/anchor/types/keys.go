package types

const (
	// ModuleName defines the module name
	ModuleName = "anchor"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// RouterKey defines the active router key
	RouterKey = ModuleName
)

var (
	// PrefixAnchorCheckpoint defines key prefix for storing the latest AnchorCheckpoint
	PrefixAnchorCheckpoint = []byte{0x30}
)
