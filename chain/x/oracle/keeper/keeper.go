package keeper

import (
	"encoding/json"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aeterna-protocol/aeterna/chain/x/oracle/types"
)

// TrustscoreKeeper defines the required interface for updating reputation scores cross-module.
type TrustscoreKeeper interface {
	RecordTaskCompletion(ctx sdk.Context, address string, success bool)
}

type Keeper struct {
	cdc              codec.BinaryCodec
	storeKey         storetypes.StoreKey
	trustscoreKeeper TrustscoreKeeper
}

func NewKeeper(cdc codec.BinaryCodec, storeKey storetypes.StoreKey, tk TrustscoreKeeper) Keeper {
	return Keeper{
		cdc:              cdc,
		storeKey:         storeKey,
		trustscoreKeeper: tk,
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
