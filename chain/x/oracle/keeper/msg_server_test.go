package keeper_test

import (
	"testing"

	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	oraclekeeper "github.com/aeterna-protocol/aeterna/chain/x/oracle/keeper"
	oracletypes "github.com/aeterna-protocol/aeterna/chain/x/oracle/types"
	trustscorekeeper "github.com/aeterna-protocol/aeterna/chain/x/trustscore/keeper"
)

func setupOracleTest(t *testing.T) (oraclekeeper.Keeper, trustscorekeeper.Keeper, sdk.Context) {
	// Share the same StoreKey prefix for unified test simulation
	key := storetypes.NewKVStoreKey("shared_test_store")
	testCtx := testutil.DefaultContextWithDB(t, key, storetypes.NewTransientStoreKey("transient_test"))

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)

	tsKeeper := trustscorekeeper.NewKeeper(cdc, key)
	oKeeper := oraclekeeper.NewKeeper(cdc, key, tsKeeper)

	return oKeeper, tsKeeper, testCtx.Ctx
}

func TestMsgSubmitProof(t *testing.T) {
	ok, tk, ctx := setupOracleTest(t)
	srv := oraclekeeper.NewMsgServerImpl(ok)

	creatorPriv := secp256k1.GenPrivKey()
	creator := sdk.AccAddress(creatorPriv.PubKey().Address()).String()

	// Proof must be exactly 128 bytes (compressed Groth16 over BN254)
	validProof := make([]byte, 128)
	for i := range validProof {
		validProof[i] = byte(i)
	}

	msg := oracletypes.NewMsgSubmitProof(
		creator,
		"task-123",
		"manifest-hash-abc",
		12, // GC content count
		2,  // Hamming distance
		"ref-hash-xyz",
		"obs-hash-123",
		validProof,
		"QmMockedIpfsCidForTest",
	)

	// 1. Submit valid proof
	res, err := srv.SubmitProof(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.True(t, res.Verified)

	// 2. Verify proof is written in oracle state
	proof, found := ok.GetTaskProof(ctx, "task-123")
	require.True(t, found)
	require.Equal(t, creator, proof.Creator)
	require.Equal(t, "manifest-hash-abc", proof.ManifestHash)
	require.True(t, proof.Verified)
	require.Equal(t, "QmMockedIpfsCidForTest", proof.IpfsCid)

	// 3. Verify trust score is updated in trustscore module (1/1 successful task = 100%)
	ts, found := tk.GetTrustScore(ctx, creator)
	require.True(t, found)
	require.Equal(t, uint32(1000000), ts.Score) // 100.00%
	require.Equal(t, uint32(1), ts.TotalTasks)
	require.Equal(t, uint32(1), ts.SuccessfulTasks)

	// 4. Submit duplicate proof for the same task (should fail)
	_, err = srv.SubmitProof(sdk.WrapSDKContext(ctx), msg)
	require.Error(t, err)

	// 5. Submit invalid proof size (should fail)
	invalidProof := make([]byte, 100)
	msgInvalidSize := oracletypes.NewMsgSubmitProof(
		creator,
		"task-456",
		"manifest-hash-abc",
		12,
		2,
		"ref-hash-xyz",
		"obs-hash-123",
		invalidProof,
		"",
	)
	_, err = srv.SubmitProof(sdk.WrapSDKContext(ctx), msgInvalidSize)
	require.Error(t, err)
}
