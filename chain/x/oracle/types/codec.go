package types

import (
	"context"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc"
)

// RegisterLegacyAminoCodec registers concrete types on the LegacyAmino codec
func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgSubmitProof{}, "oracle/MsgSubmitProof", nil)
}

// RegisterInterfaces registers the interfaces types with the interface registry
func RegisterInterfaces(registry types.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgSubmitProof{},
	)
}

var (
	Amino     = codec.NewLegacyAmino()
	ModuleCdc = codec.NewProtoCodec(types.NewInterfaceRegistry())
)

// MsgServiceDesc is the exported gRPC service descriptor for tx messages
var MsgServiceDesc = grpc.ServiceDesc{
	ServiceName: "aeterna.oracle.v1.Msg",
	HandlerType: (*MsgServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SubmitProof",
			Handler:    _Msg_SubmitProof_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "aeterna/oracle/v1/tx.proto",
}

func RegisterMsgServer(s grpc.ServiceRegistrar, srv MsgServer) {
	s.RegisterService(&MsgServiceDesc, srv)
}

// MsgServer is the server interface for Msg service.
type MsgServer interface {
	SubmitProof(context.Context, *MsgSubmitProof) (*MsgSubmitProofResponse, error)
}

func _Msg_SubmitProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MsgSubmitProof)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MsgServer).SubmitProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/aeterna.oracle.v1.Msg/SubmitProof",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MsgServer).SubmitProof(ctx, req.(*MsgSubmitProof))
	}
	return interceptor(ctx, in, info, handler)
}
