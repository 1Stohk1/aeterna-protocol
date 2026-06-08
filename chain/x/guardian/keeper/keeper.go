package keeper

import (
	"encoding/json"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aeterna-protocol/aeterna/chain/x/guardian/types"
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

// GetSBT returns the SBT record for an address
func (k Keeper) GetSBT(ctx sdk.Context, address string) (types.GuardianSBT, bool) {
	store := ctx.KVStore(k.storeKey)
	addr, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		return types.GuardianSBT{}, false
	}
	key := append(types.PrefixSBT, addr...)
	bz := store.Get(key)
	if bz == nil {
		return types.GuardianSBT{}, false
	}

	var sbt types.GuardianSBT
	err = json.Unmarshal(bz, &sbt)
	if err != nil {
		return types.GuardianSBT{}, false
	}
	return sbt, true
}

// SetSBT writes the SBT record
func (k Keeper) SetSBT(ctx sdk.Context, address string, sbt types.GuardianSBT) {
	store := ctx.KVStore(k.storeKey)
	addr, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		panic(err)
	}

	// Save primary SBT record
	key := append(types.PrefixSBT, addr...)
	bz, err := json.Marshal(&sbt)
	if err != nil {
		panic(err)
	}
	store.Set(key, bz)
}

// HasSBT checks if the address already owns an SBT
func (k Keeper) HasSBT(ctx sdk.Context, address string) bool {
	store := ctx.KVStore(k.storeKey)
	addr, err := sdk.AccAddressFromBech32(address)
	if err != nil {
		return false
	}
	key := append(types.PrefixSBT, addr...)
	return store.Has(key)
}

// HasHardwareRegistered checks if the hardware attestation hash is already bound to any owner
func (k Keeper) HasHardwareRegistered(ctx sdk.Context, tpmHash []byte) bool {
	store := ctx.KVStore(k.storeKey)
	key := append(types.PrefixTPM, tpmHash...)
	return store.Has(key)
}

// SetHardwareRegistered binds the hardware hash to an owner address
func (k Keeper) SetHardwareRegistered(ctx sdk.Context, tpmHash []byte, owner string) {
	store := ctx.KVStore(k.storeKey)
	key := append(types.PrefixTPM, tpmHash...)
	store.Set(key, []byte(owner))
}

// HasKeyRegistered checks if the Dilithium key hash is already bound to any owner
func (k Keeper) HasKeyRegistered(ctx sdk.Context, keyHash []byte) bool {
	store := ctx.KVStore(k.storeKey)
	key := append(types.PrefixKey, keyHash...)
	return store.Has(key)
}

// SetKeyRegistered binds the Dilithium key hash to an owner address
func (k Keeper) SetKeyRegistered(ctx sdk.Context, keyHash []byte, owner string) {
	store := ctx.KVStore(k.storeKey)
	key := append(types.PrefixKey, keyHash...)
	store.Set(key, []byte(owner))
}
