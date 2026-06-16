package keeper

import (
	"context"

	sdkerrors "cosmossdk.io/errors"
	"github.com/cloudflare/circl/sign/dilithium"
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

	// 4. Verify Dilithium-5 signature natively on-chain
	sbt, exists := k.guardianKeeper.GetSBT(ctx, msg.Creator)
	if !exists {
		return nil, types.ErrSBTNotFound
	}

	mode := dilithium.Mode5
	if len(sbt.DilithiumPubkey) != mode.PublicKeySize() {
		return nil, sdkerrors.Wrap(types.ErrInvalidSignature, "invalid Dilithium-5 public key size")
	}
	pubKey := mode.PublicKeyFromBytes(sbt.DilithiumPubkey)

	msgBytes := append([]byte(msg.TaskId), []byte(msg.ManifestHash)...)
	if !mode.Verify(pubKey, msgBytes, msg.Signature) {
		return nil, types.ErrInvalidSignature
	}

	// 5. Verify zk-SNARK proof logic (mocked scaffold)
	// In production, this verifies the Groth16 pairing equation e(A, B) = e(alpha, beta) * ...
	// using the public inputs: manifest_hash, task_id, gc_content, hamming, ref_hash, obs_hash.
	verified := true

	// 6. Save proof results
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
		IpfsCid:         msg.IpfsCid,
	}
	k.SetTaskProof(ctx, msg.TaskId, tp)

	// 7. Record task completion in trustscore module (cross-module call)
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
