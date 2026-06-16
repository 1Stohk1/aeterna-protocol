package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aeterna-protocol/aeterna/chain/x/guardian/types"
)

type queryServer struct {
	Keeper
}

// NewQueryServerImpl returns an implementation of the QueryServer interface
// for the provided Keeper.
func NewQueryServerImpl(keeper Keeper) types.QueryServer {
	return &queryServer{Keeper: keeper}
}

var _ types.QueryServer = queryServer{}

// GuardianSBT queries the SBT registration details for a specific address
func (q queryServer) GuardianSBT(goCtx context.Context, req *types.QueryGuardianSBTRequest) (*types.QueryGuardianSBTResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	if req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "address cannot be empty")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)

	sbt, found := q.GetSBT(ctx, req.Address)
	if !found {
		return nil, status.Error(codes.NotFound, "SBT not found for this address")
	}

	return &types.QueryGuardianSBTResponse{
		SbtId:              sbt.SbtId,
		Owner:              sbt.Owner,
		DilithiumPubkey:    sbt.DilithiumPubkey,
		ManifestoHash:      sbt.ManifestoHash,
		TrustTier:          sbt.TrustTier,
		RegistrationHeight: sbt.RegistrationHeight,
	}, nil
}
