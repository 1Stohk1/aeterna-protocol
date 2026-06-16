package types

import (
	sdkerrors "cosmossdk.io/errors"
)

var (
	// ErrDuplicateProof is returned when a proof was already submitted for a task
	ErrDuplicateProof = sdkerrors.Register(ModuleName, 1201, "proof already submitted for this task")

	// ErrInvalidProof is returned when proof validation fails
	ErrInvalidProof = sdkerrors.Register(ModuleName, 1202, "invalid zk-SNARK proof")

	// ErrInvalidSignature is returned when the Dilithium-5 signature verification fails
	ErrInvalidSignature = sdkerrors.Register(ModuleName, 1203, "invalid Dilithium-5 signature")

	// ErrSBTNotFound is returned when the creator does not have a registered SBT identity
	ErrSBTNotFound = sdkerrors.Register(ModuleName, 1204, "SBT not found for creator")
)
