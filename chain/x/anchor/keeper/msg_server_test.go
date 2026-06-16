package keeper_test

import (
	"strconv"
	"testing"

	storetypes "cosmossdk.io/store/types"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	guardiantypes "github.com/aeterna-protocol/aeterna/chain/x/guardian/types"
	anchorkeeper "github.com/aeterna-protocol/aeterna/chain/x/anchor/keeper"
	anchortypes "github.com/aeterna-protocol/aeterna/chain/x/anchor/types"
)

type mockGuardianKeeper struct {
	sbt map[string]guardiantypes.GuardianSBT
}

func (m mockGuardianKeeper) GetSBT(ctx sdk.Context, address string) (guardiantypes.GuardianSBT, bool) {
	s, found := m.sbt[address]
	return s, found
}

func setupAnchorTest(t *testing.T, gk anchorkeeper.GuardianKeeper) (anchorkeeper.Keeper, sdk.Context) {
	key := storetypes.NewKVStoreKey("anchor_test_store")
	testCtx := testutil.DefaultContextWithDB(t, key, storetypes.NewTransientStoreKey("transient_test"))

	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)

	aKeeper := anchorkeeper.NewKeeper(cdc, key, gk)

	return aKeeper, testCtx.Ctx
}

func TestMsgSubmitAnchor(t *testing.T) {
	mode := dilithium.Mode5
	pk, sk, err := mode.GenerateKey(nil)
	require.NoError(t, err)

	creatorPriv := secp256k1.GenPrivKey()
	creator := sdk.AccAddress(creatorPriv.PubKey().Address()).String()

	mockGK := mockGuardianKeeper{
		sbt: make(map[string]guardiantypes.GuardianSBT),
	}
	mockGK.sbt[creator] = guardiantypes.GuardianSBT{
		SbtId:              "SBT-test",
		Owner:              creator,
		DilithiumPubkey:    pk.Bytes(),
		ManifestoHash:      "manifesto-hash",
		TrustTier:          1,
		RegistrationHeight: 1,
	}

	ak, ctx := setupAnchorTest(t, mockGK)
	srv := anchorkeeper.NewMsgServerImpl(ak)

	blockHash := "0000000000000000000787a2a738e12a28b8e0e7a2b2512f4ef117d91e6cb1d6"
	var blockHeight uint64 = 840000
	btcTxHash := "b1a5fb7a3c8ef28292c300ff019de2a3a5f973c7132a03cf8264e1c2a13f021e"
	eventName := "heartbeat"

	// Construct signature payload: creator + block_hash + block_height + btc_tx_hash + event_name
	msgBytes := append([]byte(creator), []byte(blockHash)...)
	msgBytes = append(msgBytes, []byte(strconv.FormatUint(blockHeight, 10))...)
	msgBytes = append(msgBytes, []byte(btcTxHash)...)
	msgBytes = append(msgBytes, []byte(eventName)...)
	signature := mode.Sign(sk, msgBytes)

	// 1. Submit valid anchor
	msg := anchortypes.NewMsgSubmitAnchor(
		creator,
		blockHash,
		blockHeight,
		btcTxHash,
		eventName,
		signature,
	)
	res, err := srv.SubmitAnchor(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.True(t, res.Success)

	// 2. Verify state persistence
	latest, found := ak.GetLatestAnchor(ctx)
	require.True(t, found)
	require.Equal(t, creator, latest.Creator)
	require.Equal(t, blockHash, latest.BlockHash)
	require.Equal(t, blockHeight, latest.BlockHeight)
	require.Equal(t, btcTxHash, latest.BtcTxHash)
	require.Equal(t, eventName, latest.EventName)
	require.NotEmpty(t, latest.Timestamp)

	// 3. Submit anchor with invalid signature (different block height)
	invalidMsg := anchortypes.NewMsgSubmitAnchor(
		creator,
		blockHash,
		blockHeight+1, // signature will not match
		btcTxHash,
		eventName,
		signature,
	)
	_, err = srv.SubmitAnchor(sdk.WrapSDKContext(ctx), invalidMsg)
	require.Error(t, err)
	require.ErrorIs(t, err, anchortypes.ErrInvalidSignature)

	// 4. Submit anchor with unregistered creator (missing SBT)
	unregisteredCreatorPriv := secp256k1.GenPrivKey()
	unregisteredCreator := sdk.AccAddress(unregisteredCreatorPriv.PubKey().Address()).String()
	unregisteredMsg := anchortypes.NewMsgSubmitAnchor(
		unregisteredCreator,
		blockHash,
		blockHeight,
		btcTxHash,
		eventName,
		signature,
	)
	_, err = srv.SubmitAnchor(sdk.WrapSDKContext(ctx), unregisteredMsg)
	require.Error(t, err)
	require.ErrorIs(t, err, anchortypes.ErrSBTNotFound)

	// 5. Submit anchor with invalid Dilithium public key size in SBT
	invalidPKCreatorPriv := secp256k1.GenPrivKey()
	invalidPKCreator := sdk.AccAddress(invalidPKCreatorPriv.PubKey().Address()).String()
	mockGK.sbt[invalidPKCreator] = guardiantypes.GuardianSBT{
		SbtId:           "SBT-invalid-pk",
		Owner:           invalidPKCreator,
		DilithiumPubkey: []byte("too-short"), // invalid pubkey size
	}
	invalidPKMsg := anchortypes.NewMsgSubmitAnchor(
		invalidPKCreator,
		blockHash,
		blockHeight,
		btcTxHash,
		eventName,
		signature,
	)
	_, err = srv.SubmitAnchor(sdk.WrapSDKContext(ctx), invalidPKMsg)
	require.Error(t, err)
	require.ErrorIs(t, err, anchortypes.ErrInvalidSignature)
}
