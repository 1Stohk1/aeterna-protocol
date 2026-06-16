package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgSubmitAnchor{}

// MsgSubmitAnchor submits a signed Bitcoin anchor transaction.
type MsgSubmitAnchor struct {
	Creator     string `json:"creator"`
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	BtcTxHash   string `json:"btc_tx_hash"`
	EventName   string `json:"event_name"`
	Signature   []byte `json:"signature"`
}

func NewMsgSubmitAnchor(
	creator string,
	blockHash string,
	blockHeight uint64,
	btcTxHash string,
	eventName string,
	signature []byte,
) *MsgSubmitAnchor {
	return &MsgSubmitAnchor{
		Creator:     creator,
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		BtcTxHash:   btcTxHash,
		EventName:   eventName,
		Signature:   signature,
	}
}

func (msg *MsgSubmitAnchor) Route() string {
	return RouterKey
}

func (msg *MsgSubmitAnchor) Type() string {
	return "SubmitAnchor"
}

func (msg *MsgSubmitAnchor) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return sdkerrors.ErrInvalidAddress.Wrapf("invalid creator address (%s)", err)
	}
	if len(msg.BlockHash) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("block hash cannot be empty")
	}
	if msg.BlockHeight == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("block height must be greater than zero")
	}
	if len(msg.BtcTxHash) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("BTC transaction hash cannot be empty")
	}
	if len(msg.Signature) == 0 {
		return sdkerrors.ErrInvalidRequest.Wrap("signature cannot be empty")
	}
	return nil
}

func (msg *MsgSubmitAnchor) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

func (msg *MsgSubmitAnchor) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

func (msg *MsgSubmitAnchor) Reset() {
	*msg = MsgSubmitAnchor{}
}

func (msg *MsgSubmitAnchor) String() string {
	return msg.Creator
}

func (msg *MsgSubmitAnchor) ProtoMessage() {}

// MsgSubmitAnchorResponse is returned upon successful anchor submission.
type MsgSubmitAnchorResponse struct {
	Success bool `json:"success"`
}

func (msg *MsgSubmitAnchorResponse) Reset() {
	*msg = MsgSubmitAnchorResponse{}
}

func (msg *MsgSubmitAnchorResponse) String() string {
	if msg.Success {
		return "true"
	}
	return "false"
}

func (msg *MsgSubmitAnchorResponse) ProtoMessage() {}
