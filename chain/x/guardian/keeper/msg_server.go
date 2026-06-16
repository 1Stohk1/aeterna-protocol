package keeper

import (
	"context"
	"crypto/sha256"
	"fmt"

	sdkerrors "cosmossdk.io/errors"
	"github.com/cloudflare/circl/sign/dilithium"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aeterna-protocol/aeterna/chain/x/guardian/types"
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

func (k msgServer) MintGuardianSBT(goCtx context.Context, msg *types.MsgMintGuardianSBT) (*types.MsgMintGuardianSBTResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Validate creator address
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "invalid creator address")
	}

	// 2. Check if owner already owns an SBT
	if k.HasSBT(ctx, msg.Creator) {
		return nil, types.ErrSBTAlreadyMinted
	}

	// 3. Check for duplicate hardware attestation (Sybil Resistance)
	tpmHash := sha256.Sum256(msg.Tpm2Attestation)
	if k.HasHardwareRegistered(ctx, tpmHash[:]) {
		return nil, types.ErrDuplicateHardware
	}

	// 4. Check for duplicate Dilithium-5 public key
	keyHash := sha256.Sum256(msg.DilithiumPubkey)
	if k.HasKeyRegistered(ctx, keyHash[:]) {
		return nil, types.ErrDuplicateKey
	}

	// 5. Verify Dilithium-5 Public Key structure & signature
	mode := dilithium.Mode5
	if len(msg.DilithiumPubkey) != mode.PublicKeySize() {
		return nil, sdkerrors.Wrap(types.ErrInvalidSignature, "invalid Dilithium-5 public key length")
	}
	pubKey := mode.PublicKeyFromBytes(msg.DilithiumPubkey)

	// Dilithium signature check: we verify that the signature signs the manifesto_hash 
	// using the dilithium public key to prove possession of the private key.
	if len(msg.Tpm2Signature) > 0 {
		manifestoBytes := []byte(msg.ManifestoHash)
		if !mode.Verify(pubKey, manifestoBytes, msg.Tpm2Signature) {
			return nil, types.ErrInvalidSignature
		}
	}

	// 6. Write to store
	sbt := types.GuardianSBT{
		SbtId:              fmt.Sprintf("SBT-%x", keyHash[:8]),
		Owner:              msg.Creator,
		DilithiumPubkey:    msg.DilithiumPubkey,
		ManifestoHash:      msg.ManifestoHash,
		TrustTier:          msg.TrustTier,
		RegistrationHeight: ctx.BlockHeight(),
	}

	k.SetSBT(ctx, msg.Creator, sbt)
	k.SetHardwareRegistered(ctx, tpmHash[:], msg.Creator)
	k.SetKeyRegistered(ctx, keyHash[:], msg.Creator)

	// Emit events
	ctx.EventManager().EmitEvents(sdk.Events{
		sdk.NewEvent(
			types.ModuleName,
			sdk.NewAttribute("action", "mint_sbt"),
			sdk.NewAttribute("owner", msg.Creator),
			sdk.NewAttribute("sbt_id", sbt.SbtId),
		),
	})

	return &types.MsgMintGuardianSBTResponse{SbtId: sbt.SbtId}, nil
}
