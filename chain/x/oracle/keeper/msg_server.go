package keeper

import (
	"context"

	sdkerrors "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aeterna-protocol/aeterna/chain/x/oracle/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
// for the provided Keeper.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

// SubmitProof handles task proof submissions, verifies them, stores results, and updates trust scores.
func (k msgServer) SubmitProof(goCtx context.Context, msg *types.MsgSubmitProof) (*types.MsgSubmitProofResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Validate creator address
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "invalid creator address")
	}

	// 2. Check if proof was already submitted for this task to prevent double submissions
	if _, found := k.GetTaskProof(ctx, msg.TaskId); found {
		return nil, types.ErrDuplicateProof
	}

	// 3. Verify proof length is exactly 128 bytes (compressed Groth16 over BN254)
	if len(msg.Proof) != 128 {
		return nil, sdkerrors.Wrapf(types.ErrInvalidProof, "expected exactly 128 bytes, got %d", len(msg.Proof))
	}

	// 4. Verify zk-SNARK proof logic (mocked scaffold)
	// In production, this verifies the Groth16 pairing equation e(A, B) = e(alpha, beta) * ...
	// using the public inputs: manifest_hash, task_id, gc_content, hamming, ref_hash, obs_hash.
	verified := true

	// 5. Save proof results
	tp := types.TaskProof{
		TaskId:          msg.TaskId,
		Creator:         msg.Creator,
		ManifestHash:    msg.ManifestHash,
		GcContentCount:  msg.GcContentCount,
		HammingDistance: msg.HammingDistance,
		RefHash:         msg.RefHash,
		ObsHash:         msg.ObsHash,
		Proof:           msg.Proof,
		Verified:        verified,
		Height:          ctx.BlockHeight(),
	}
	k.SetTaskProof(ctx, msg.TaskId, tp)

	// 6. Record task completion in trustscore module (cross-module call)
	k.trustscoreKeeper.RecordTaskCompletion(ctx, msg.Creator, verified)

	// Emit event
	ctx.EventManager().EmitEvents(sdk.Events{
		sdk.NewEvent(
			types.ModuleName,
			sdk.NewAttribute("action", "submit_proof"),
			sdk.NewAttribute("creator", msg.Creator),
			sdk.NewAttribute("task_id", msg.TaskId),
			sdk.NewAttribute("verified", "true"),
		),
	})

	return &types.MsgSubmitProofResponse{Verified: verified}, nil
}
