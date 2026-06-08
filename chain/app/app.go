package app

import (
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/aeterna-protocol/aeterna/chain/x/guardian"
	"github.com/aeterna-protocol/aeterna/chain/x/guardian/keeper"
)

type App struct {
	LegacyAmino       *codec.LegacyAmino
	InterfaceRegistry types.InterfaceRegistry
	AppCodec          codec.Codec

	GuardianKeeper keeper.Keeper
	ModuleManager  *module.Manager
}

func NewApp(
	appCodec codec.Codec,
	legacyAmino *codec.LegacyAmino,
	interfaceRegistry types.InterfaceRegistry,
	storeKey storetypes.StoreKey,
) *App {
	gKeeper := keeper.NewKeeper(appCodec, storeKey)
	gModule := guardian.NewAppModule(gKeeper)

	// Setup module manager
	mm := module.NewManager(gModule)

	return &App{
		LegacyAmino:       legacyAmino,
		InterfaceRegistry: interfaceRegistry,
		AppCodec:          appCodec,
		GuardianKeeper:    gKeeper,
		ModuleManager:     mm,
	}
}
