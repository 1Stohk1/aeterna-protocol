package types

import (
	sdkerrors "cosmossdk.io/errors"
)

var (
	// ErrInvalidSignature is returned when Dilithium-5 verification fails.
	ErrInvalidSignature = sdkerrors.Register(ModuleName, 1301, "invalid Dilithium-5 signature")

	// ErrSBTNotFound is returned when the creator node is not registered as a Guardian.
	ErrSBTNotFound = sdkerrors.Register(ModuleName, 1302, "SBT not found for creator")
)
