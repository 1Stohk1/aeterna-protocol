package app

import (
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/aeterna-protocol/aeterna/chain/x/guardian"
	guardiankeeper "github.com/aeterna-protocol/aeterna/chain/x/guardian/keeper"
	"github.com/aeterna-protocol/aeterna/chain/x/oracle"
	oraclekeeper "github.com/aeterna-protocol/aeterna/chain/x/oracle/keeper"
	"github.com/aeterna-protocol/aeterna/chain/x/trustscore"
	trustscorekeeper "github.com/aeterna-protocol/aeterna/chain/x/trustscore/keeper"
	"github.com/aeterna-protocol/aeterna/chain/x/anchor"
	anchorkeeper "github.com/aeterna-protocol/aeterna/chain/x/anchor/keeper"
)

type App struct {
	LegacyAmino       *codec.LegacyAmino
	InterfaceRegistry types.InterfaceRegistry
	AppCodec          codec.Codec

	GuardianKeeper   guardiankeeper.Keeper
	OracleKeeper     oraclekeeper.Keeper
	TrustscoreKeeper trustscorekeeper.Keeper
	AnchorKeeper     anchorkeeper.Keeper
	ModuleManager    *module.Manager
}

func NewApp(
	appCodec codec.Codec,
	legacyAmino *codec.LegacyAmino,
	interfaceRegistry types.InterfaceRegistry,
	storeKey storetypes.StoreKey,
) *App {
	// 1. Initialize Guardian Module
	gKeeper := guardiankeeper.NewKeeper(appCodec, storeKey)
	gModule := guardian.NewAppModule(gKeeper)

	// 2. Initialize Trustscore Module
	tsKeeper := trustscorekeeper.NewKeeper(appCodec, storeKey)
	tsModule := trustscore.NewAppModule(tsKeeper)

	// 3. Initialize Oracle Module (injecting tsKeeper and gKeeper dependencies)
	oKeeper := oraclekeeper.NewKeeper(appCodec, storeKey, tsKeeper, gKeeper)
	oModule := oracle.NewAppModule(oKeeper)

	// 4. Initialize Anchor Module (injecting gKeeper dependency)
	aKeeper := anchorkeeper.NewKeeper(appCodec, storeKey, gKeeper)
	aModule := anchor.NewAppModule(aKeeper)

	// 5. Setup module manager registering all four modules
	mm := module.NewManager(gModule, tsModule, oModule, aModule)

	return &App{
		LegacyAmino:       legacyAmino,
		InterfaceRegistry: interfaceRegistry,
		AppCodec:          appCodec,
		GuardianKeeper:    gKeeper,
		OracleKeeper:      oKeeper,
		TrustscoreKeeper:  tsKeeper,
		AnchorKeeper:      aKeeper,
		ModuleManager:     mm,
	}
}
