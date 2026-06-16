package keeper

import (
	"encoding/json"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	guardiantypes "github.com/aeterna-protocol/aeterna/chain/x/guardian/types"
	"github.com/aeterna-protocol/aeterna/chain/x/anchor/types"
)

// GuardianKeeper defines the required interface for retrieving SBT records from the guardian module.
type GuardianKeeper interface {
	GetSBT(ctx sdk.Context, address string) (guardiantypes.GuardianSBT, bool)
}

type Keeper struct {
	cdc            codec.BinaryCodec
	storeKey       storetypes.StoreKey
	guardianKeeper GuardianKeeper
}

func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey, gk GuardianKeeper) Keeper {
	return Keeper{
		cdc:            cdc,
		storeKey:       storeKey,
		guardianKeeper: gk,
	}
}

// GetLatestAnchor returns the latest submitted AnchorCheckpoint record
func (k Keeper) GetLatestAnchor(ctx sdk.Context) (types.AnchorCheckpoint, bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.PrefixAnchorCheckpoint)
	if bz == nil {
		return types.AnchorCheckpoint{}, false
	}

	var ac types.AnchorCheckpoint
	err := json.Unmarshal(bz, &ac)
	if err != nil {
		return types.AnchorCheckpoint{}, false
	}
	return ac, true
}

// SetLatestAnchor writes the latest AnchorCheckpoint record
func (k Keeper) SetLatestAnchor(ctx sdk.Context, ac types.AnchorCheckpoint) {
	store := ctx.KVStore(k.storeKey)
	bz, err := json.Marshal(&ac)
	if err != nil {
		panic(err)
	}
	store.Set(types.PrefixAnchorCheckpoint, bz)
}
