package types

import (
	sdkerrors "cosmossdk.io/errors"
)

var (
	// ErrDuplicateProof is returned when a proof was already submitted for a task
	ErrDuplicateProof = sdkerrors.Register(ModuleName, 1201, "proof already submitted for this task")

	// ErrInvalidProof is returned when proof validation fails
	ErrInvalidProof = sdkerrors.Register(ModuleName, 1202, "invalid zk-SNARK proof")
)
