package keeper_test

import (
	"testing"

	storetypes "cosmossdk.io/store/types"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/aeterna-protocol/aeterna/chain/x/guardian/keeper"
	"github.com/aeterna-protocol/aeterna/chain/x/guardian/types"
)

func setupKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	key := storetypes.NewKVStoreKey(types.StoreKey)
	testCtx := testutil.DefaultContextWithDB(t, key, storetypes.NewTransientStoreKey("transient_test"))
	
	registry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(registry)
	
	return keeper.NewKeeper(cdc, key), testCtx.Ctx
}

func TestKeeperMintSBT(t *testing.T) {
	k, ctx := setupKeeper(t)
	srv := keeper.NewMsgServerImpl(k)

	// 1. Generate PQC Dilithium-5 Keypair for the Guardian
	mode := dilithium.Mode5
	pubKey, privKey, err := mode.GenerateKey(nil)
	require.NoError(t, err)

	pubKeyBytes := pubKey.Bytes()

	// 2. Sign the manifesto hash with Dilithium-5 key to prove ownership
	manifestoHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sig := mode.Sign(privKey, []byte(manifestoHash))

	// 3. Dynamically generate valid Cosmos address
	creatorPriv := secp256k1.GenPrivKey()
	creator := sdk.AccAddress(creatorPriv.PubKey().Address()).String()
	tpmAttestation := []byte("hardware_attestation_tpm2_prometheus_0")

	// 4. Mint the SBT
	msg := types.NewMsgMintGuardianSBT(
		creator,
		pubKeyBytes,
		tpmAttestation,
		sig,
		manifestoHash,
		1, // Tier: Guardiano
	)

	res, err := srv.MintGuardianSBT(sdk.WrapSDKContext(ctx), msg)
	require.NoError(t, err)
	require.NotEmpty(t, res.SbtId)

	// 5. Verify SBT is stored correctly in the database
	sbt, found := k.GetSBT(ctx, creator)
	require.True(t, found)
	require.Equal(t, creator, sbt.Owner)
	require.Equal(t, manifestoHash, sbt.ManifestoHash)
	require.Equal(t, pubKeyBytes, sbt.DilithiumPubkey)
	require.Equal(t, uint32(1), sbt.TrustTier)

	// 6. Test uniqueness: Owner already owns an SBT
	_, err = srv.MintGuardianSBT(sdk.WrapSDKContext(ctx), msg)
	require.ErrorIs(t, err, types.ErrSBTAlreadyMinted)

	// 7. Test uniqueness: Duplicate TPM2 attestation (Sybil Resistance check)
	creatorPriv2 := secp256k1.GenPrivKey()
	creator2 := sdk.AccAddress(creatorPriv2.PubKey().Address()).String()
	
	pubKey2, privKey2, _ := mode.GenerateKey(nil)
	pubKeyBytes2 := pubKey2.Bytes()
	sig2 := mode.Sign(privKey2, []byte(manifestoHash))

	msgDupTPM := types.NewMsgMintGuardianSBT(
		creator2,
		pubKeyBytes2,
		tpmAttestation, // Duplicate attestation
		sig2,
		manifestoHash,
		1,
	)
	_, err = srv.MintGuardianSBT(sdk.WrapSDKContext(ctx), msgDupTPM)
	require.ErrorIs(t, err, types.ErrDuplicateHardware)

	// 8. Test uniqueness: Duplicate Dilithium-5 Key
	tpmAttestation2 := []byte("hardware_attestation_tpm2_prometheus_1")
	msgDupKey := types.NewMsgMintGuardianSBT(
		creator2,
		pubKeyBytes, // Duplicate Dilithium-5 key
		tpmAttestation2,
		sig2,
		manifestoHash,
		1,
	)
	_, err = srv.MintGuardianSBT(sdk.WrapSDKContext(ctx), msgDupKey)
	require.ErrorIs(t, err, types.ErrDuplicateKey)
}

func TestKeeperInvalidSignature(t *testing.T) {
	k, ctx := setupKeeper(t)
	srv := keeper.NewMsgServerImpl(k)

	mode := dilithium.Mode5
	pubKey, _, _ := mode.GenerateKey(nil)
	pubKeyBytes := pubKey.Bytes()

	creatorPriv := secp256k1.GenPrivKey()
	creator := sdk.AccAddress(creatorPriv.PubKey().Address()).String()
	tpmAttestation := []byte("hardware_attestation_tpm2_prometheus_0")
	manifestoHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	badSig := []byte("invalid_signature_bytes_1234567890")

	msg := types.NewMsgMintGuardianSBT(
		creator,
		pubKeyBytes,
		tpmAttestation,
		badSig,
		manifestoHash,
		1,
	)

	_, err := srv.MintGuardianSBT(sdk.WrapSDKContext(ctx), msg)
	require.ErrorIs(t, err, types.ErrInvalidSignature)
}
