package types

import (
	sdkerrors "cosmossdk.io/errors"
)

var (
	// ErrGuardianNotFound is returned when a requested guardian has no registered trust score
	ErrGuardianNotFound = sdkerrors.Register(ModuleName, 1301, "guardian not found")
)
