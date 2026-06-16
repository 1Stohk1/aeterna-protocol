package keeper

import (
	"context"
	"strconv"
	"time"

	sdkerrors "cosmossdk.io/errors"
	"github.com/cloudflare/circl/sign/dilithium"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aeterna-protocol/aeterna/chain/x/anchor/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface for the provided Keeper.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// SubmitAnchor handles anchor checkpoint submissions, verifies they are authorized, and persists them.
func (k msgServer) SubmitAnchor(goCtx context.Context, msg *types.MsgSubmitAnchor) (*types.MsgSubmitAnchorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Validate creator address
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "invalid creator address")
	}

	// 2. Fetch the creator's SBT
	sbt, exists := k.guardianKeeper.GetSBT(ctx, msg.Creator)
	if !exists {
		return nil, types.ErrSBTNotFound
	}

	// 3. Verify Dilithium-5 signature natively on-chain
	mode := dilithium.Mode5
	if len(sbt.DilithiumPubkey) != mode.PublicKeySize() {
		return nil, sdkerrors.Wrap(types.ErrInvalidSignature, "invalid Dilithium-5 public key size")
	}
	pubKey := mode.PublicKeyFromBytes(sbt.DilithiumPubkey)

	// Construct message to verify: creator + block_hash + block_height + btc_tx_hash + event_name
	msgBytes := append([]byte(msg.Creator), []byte(msg.BlockHash)...)
	msgBytes = append(msgBytes, []byte(strconv.FormatUint(msg.BlockHeight, 10))...)
	msgBytes = append(msgBytes, []byte(msg.BtcTxHash)...)
	msgBytes = append(msgBytes, []byte(msg.EventName)...)

	if !mode.Verify(pubKey, msgBytes, msg.Signature) {
		return nil, types.ErrInvalidSignature
	}

	// 4. Save checkpoint record
	ac := types.AnchorCheckpoint{
		BtcTxHash:   msg.BtcTxHash,
		BlockHash:   msg.BlockHash,
		BlockHeight: msg.BlockHeight,
		Creator:     msg.Creator,
		EventName:   msg.EventName,
		Timestamp:   time.Now().Unix(),
	}
	k.SetLatestAnchor(ctx, ac)

	// 5. Emit events
	ctx.EventManager().EmitEvents(sdk.Events{
		sdk.NewEvent(
			types.ModuleName,
			sdk.NewAttribute("action", "submit_anchor"),
			sdk.NewAttribute("creator", msg.Creator),
			sdk.NewAttribute("btc_tx_hash", msg.BtcTxHash),
			sdk.NewAttribute("block_hash", msg.BlockHash),
			sdk.NewAttribute("block_height", strconv.FormatUint(msg.BlockHeight, 10)),
			sdk.NewAttribute("event_name", msg.EventName),
		),
	})

	return &types.MsgSubmitAnchorResponse{Success: true}, nil
}
