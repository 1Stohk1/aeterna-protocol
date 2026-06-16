package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgMintGuardianSBT{}

// MsgMintGuardianSBT defines a transaction message to register a node and mint an SBT
type MsgMintGuardianSBT struct {
	Creator         string `json:"creator"`
	DilithiumPubkey []byte `json:"dilithium_pubkey"`
	Tpm2Attestation []byte `json:"tpm2_attestation"`
	Tpm2Signature   []byte `json:"tpm2_signature"`
	ManifestoHash   string `json:"manifesto_hash"`
	TrustTier       uint32 `json:"trust_tier"`
}

func NewMsgMintGuardianSBT(creator string, dilithiumPubkey, tpm2Attestation, tpm2Signature []byte, manifestoHash string, trustTier uint32) *MsgMintGuardianSBT {
	return &MsgMintGuardianSBT{
		Creator:         creator,
		DilithiumPubkey: dilithiumPubkey,
		Tpm2Attestation: tpm2Attestation,
		Tpm2Signature:   tpm2Signature,
		ManifestoHash:   manifestoHash,
		TrustTier:       trustTier,
	}
}

func (msg *MsgMintGuardianSBT) Route() string {
	return RouterKey
}

func (msg *MsgMintGuardianSBT) Type() string {
	return "MintGuardianSBT"
}

func (msg *MsgMintGuardianSBT) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.ErrInvalidAddress.Wrapf("invalid creator address (%s)", err)
	}
	if len(msg.DilithiumPubkey) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("dilithium public key cannot be empty")
	}
	if len(msg.Tpm2Attestation) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("TPM2 attestation quote cannot be empty")
	}
	if len(msg.ManifestoHash) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("manifesto hash cannot be empty")
	}
	return nil
}

func (msg *MsgMintGuardianSBT) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

func (msg *MsgMintGuardianSBT) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

func (msg *MsgMintGuardianSBT) Reset() {
	*msg = MsgMintGuardianSBT{}
}

func (msg *MsgMintGuardianSBT) String() string {
	return msg.Creator
}

func (msg *MsgMintGuardianSBT) ProtoMessage() {}

// MsgMintGuardianSBTResponse is returned upon successful minting
type MsgMintGuardianSBTResponse struct {
	SbtId string `json:"sbt_id"`
}

func (msg *MsgMintGuardianSBTResponse) Reset() {
	*msg = MsgMintGuardianSBTResponse{}
}

func (msg *MsgMintGuardianSBTResponse) String() string {
	return msg.SbtId
}

func (msg *MsgMintGuardianSBTResponse) ProtoMessage() {}
