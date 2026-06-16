package keeper

import (
	"encoding/json"
	"fmt"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aeterna-protocol/aeterna/chain/x/trustscore/types"
)

type Keeper struct {
	cdc      codec.BinaryCodec
	storeKey storetypes.StoreKey
}

func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey) Keeper {
	return Keeper{
		cdc:      cdc,
		storeKey: storeKey,
	}
}

// GetTrustScore returns the reputation record for an address
func (k Keeper) GetTrustScore(ctx sdk.Context, address string) (types.TrustScore, bool) {
	store := ctx.KVStore(k.storeKey)
	addr, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		return types.TrustScore{}, false
	}
	key := append(types.PrefixTrustScore, addr...)
	bz := store.Get(key)
	if bz == nil {
		return types.TrustScore{}, false
	}

	var ts types.TrustScore
	err = json.Unmarshal(bz, &ts)
	if err != nil {
		return types.TrustScore{}, false
	}
	return ts, true
}

// SetTrustScore writes the reputation record to store
func (k Keeper) SetTrustScore(ctx sdk.Context, address string, ts types.TrustScore) {
	store := ctx.KVStore(k.storeKey)
	addr, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		panic(err)
	}
	key := append(types.PrefixTrustScore, addr...)
	bz, err := json.Marshal(&ts)
	if err != nil {
		panic(err)
	}
	store.Set(key, bz)
}

// RecordTaskCompletion updates the score based on successful/failed tasks
func (k Keeper) RecordTaskCompletion(ctx sdk.Context, address string, success bool) {
	ts, found := k.GetTrustScore(ctx, address)
	if !found {
		ts = types.TrustScore{
			GuardianAddress: address,
			Score:           1000000, // Initial default score is 100.00%
			TotalTasks:      0,
			SuccessfulTasks: 0,
			LastUpdated:     ctx.BlockHeight(),
		}
	}

	ts.TotalTasks++
	if success {
		ts.SuccessfulTasks++
	}

	// Calculate fixed-point score: (SuccessfulTasks / TotalTasks) * 1,000,000
	if ts.TotalTasks > 0 {
		ts.Score = uint32((uint64(ts.SuccessfulTasks) * 1000000) / uint64(ts.TotalTasks))
	} else {
		ts.Score = 1000000
	}
	ts.LastUpdated = ctx.BlockHeight()

	k.SetTrustScore(ctx, address, ts)

	// Emit event
	ctx.EventManager().EmitEvents(sdk.Events{
		sdk.NewEvent(
			types.ModuleName,
			sdk.NewAttribute("action", "update_trust_score"),
			sdk.NewAttribute("guardian", address),
			sdk.NewAttribute("score", fmt.Sprintf("%d", ts.Score)),
			sdk.NewAttribute("total_tasks", fmt.Sprintf("%d", ts.TotalTasks)),
		),
	})
}
