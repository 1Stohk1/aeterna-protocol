package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgSubmitProof{}

// MsgSubmitProof submits a verified zk-SNARK task execution proof.
type MsgSubmitProof struct {
	Creator         string `json:"creator"`
	TaskId          string `json:"task_id"`
	ManifestHash    string `json:"manifest_hash"`
	GcContentCount  uint32 `json:"gc_content_count"`
	HammingDistance uint32 `json:"hamming_distance"`
	RefHash         string `json:"ref_hash"`
	ObsHash         string `json:"obs_hash"`
	Proof           []byte `json:"proof"`
	IpfsCid         string `json:"ipfs_cid,omitempty"`
}

func NewMsgSubmitProof(
	creator, taskId, manifestHash string,
	gcContentCount, hammingDistance uint32,
	refHash, obsHash string,
	proof []byte,
	ipfsCid string,
) *MsgSubmitProof {
	return &MsgSubmitProof{
		Creator:         creator,
		TaskId:          taskId,
		ManifestHash:    manifestHash,
		GcContentCount:  gcContentCount,
		HammingDistance: hammingDistance,
		RefHash:         refHash,
		ObsHash:         obsHash,
		Proof:           proof,
		IpfsCid:         ipfsCid,
	}
}

func (msg *MsgSubmitProof) Route() string {
	return RouterKey
}

func (msg *MsgSubmitProof) Type() string {
	return "SubmitProof"
}

func (msg *MsgSubmitProof) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.ErrInvalidAddress.Wrapf("invalid creator address (%s)", err)
	}
	if len(msg.TaskId) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("task ID cannot be empty")
	}
	if len(msg.ManifestHash) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("manifest hash cannot be empty")
	}
	if len(msg.RefHash) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("reference sequence hash cannot be empty")
	}
	if len(msg.ObsHash) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("observed sequence hash cannot be empty")
	}
	// Compressed Groth16 proof on BN254 must be exactly 128 bytes
	if len(msg.Proof) != 128 {
		return sdkerrors.ErrInvalidRequest.Wrapf("invalid zk-SNARK proof size: expected exactly 128 bytes, got %d", len(msg.Proof))
	}
	return nil
}

func (msg *MsgSubmitProof) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

func (msg *MsgSubmitProof) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

func (msg *MsgSubmitProof) Reset() {
	*msg = MsgSubmitProof{}
}

func (msg *MsgSubmitProof) String() string {
	return msg.Creator
}

func (msg *MsgSubmitProof) ProtoMessage() {}

// MsgSubmitProofResponse is returned upon successful submission
type MsgSubmitProofResponse struct {
	Verified bool `json:"verified"`
}

func (msg *MsgSubmitProofResponse) Reset() {
	*msg = MsgSubmitProofResponse{}
}

func (msg *MsgSubmitProofResponse) String() string {
	if msg.Verified {
		return "true"
	}
	return "false"
}

func (msg *MsgSubmitProofResponse) ProtoMessage() {}
