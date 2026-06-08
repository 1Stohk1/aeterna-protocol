package types

import (
	sdkerrors "cosmossdk.io/errors"
)

var (
	// ErrSBTAlreadyMinted is returned when an address already owns an SBT
	ErrSBTAlreadyMinted = sdkerrors.Register(ModuleName, 1101, "address already owns an identity token")

	// ErrDuplicateHardware is returned when a physical TPM2 attestation is already registered
	ErrDuplicateHardware = sdkerrors.Register(ModuleName, 1102, "physical TPM2 attestation already registered")

	// ErrDuplicateKey is returned when a Dilithium key is already bound to an identity
	ErrDuplicateKey = sdkerrors.Register(ModuleName, 1103, "cryptographic key already bound to an identity")

	// ErrInvalidSignature is returned when signature validation fails
	ErrInvalidSignature = sdkerrors.Register(ModuleName, 1104, "invalid Dilithium-5 signature")

	// ErrInvalidAttestation is returned when TPM2 attestation quote verification fails
	ErrInvalidAttestation = sdkerrors.Register(ModuleName, 1105, "invalid TPM2 attestation quote or signature")
)
