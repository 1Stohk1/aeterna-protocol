package types

const (
	// ModuleName defines the module name
	ModuleName = "guardian"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// RouterKey defines the module's message routing key
	RouterKey = ModuleName

	// QuerierRoute defines the module's query routing path
	QuerierRoute = ModuleName
)

var (
	// PrefixSBT defines key prefix for storing SBT records: PrefixSBT + Address
	PrefixSBT = []byte{0x01}

	// PrefixTPM defines key prefix for checking duplicate hardware attestation hash: PrefixTPM + Hash
	PrefixTPM = []byte{0x02}

	// PrefixKey defines key prefix for checking duplicate Dilithium keys: PrefixKey + Hash
	PrefixKey = []byte{0x03}
)
