package keeper

import (
	"encoding/json"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	guardiantypes "github.com/aeterna-protocol/aeterna/chain/x/guardian/types"
	"github.com/aeterna-protocol/aeterna/chain/x/oracle/types"
)

// TrustscoreKeeper defines the required interface for updating reputation scores cross-module.
type TrustscoreKeeper interface {
	RecordTaskCompletion(ctx sdk.Context, address string, success bool)
}

// GuardianKeeper defines the required interface for retrieving SBT records from the guardian module.
type GuardianKeeper interface {
	GetSBT(ctx sdk.Context, address string) (guardiantypes.GuardianSBT, bool)
}

type Keeper struct {
	cdc              codec.BinaryCodec
	storeKey         storetypes.StoreKey
	trustscoreKeeper TrustscoreKeeper
	guardianKeeper   GuardianKeeper
}

func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey, tk TrustscoreKeeper, gk GuardianKeeper) Keeper {
	return Keeper{
		cdc:              cdc,
		storeKey:         storeKey,
		trustscoreKeeper: tk,
		guardianKeeper:   gk,
	}
}

// GetTaskProof returns a submitted task proof record by taskId
func (k Keeper) GetTaskProof(ctx sdk.Context, taskId string) (types.TaskProof, bool) {
	store := ctx.KVStore(k.storeKey)
	key := append(types.PrefixTaskProof, []byte(taskId)...)
	bz := store.Get(key)
	if bz == nil {
		return types.TaskProof{}, false
	}

	var tp types.TaskProof
	err := json.Unmarshal(bz, &tp)
	if err != nil {
		return types.TaskProof{}, false
	}
	return tp, true
}

// SetTaskProof writes a task proof record
func (k Keeper) SetTaskProof(ctx sdk.Context, taskId string, tp types.TaskProof) {
	store := ctx.KVStore(k.storeKey)
	key := append(types.PrefixTaskProof, []byte(taskId)...)
	bz, err := json.Marshal(&tp)
	if err != nil {
		panic(err)
	}
	store.Set(key, bz)
}
