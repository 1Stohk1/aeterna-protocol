package types

import (
	"context"
	
	"google.golang.org/grpc"
)

// QueryServer is the server interface for Query service.
type QueryServer interface {
	GuardianSBT(context.Context, *QueryGuardianSBTRequest) (*QueryGuardianSBTResponse, error)
}

// QueryGuardianSBTRequest is the request type for the Query/GuardianSBT RPC method.
type QueryGuardianSBTRequest struct {
	Address string `json:"address"`
}

func (msg *QueryGuardianSBTRequest) Reset() {
	*msg = QueryGuardianSBTRequest{}
}

func (msg *QueryGuardianSBTRequest) String() string {
	return msg.Address
}

func (msg *QueryGuardianSBTRequest) ProtoMessage() {}

// QueryGuardianSBTResponse is the response type for the Query/GuardianSBT RPC method.
type QueryGuardianSBTResponse struct {
	SbtId              string `json:"sbt_id"`
	Owner              string `json:"owner"`
	DilithiumPubkey    []byte `json:"dilithium_pubkey"`
	ManifestoHash      string `json:"manifesto_hash"`
	TrustTier          uint32 `json:"trust_tier"`
	RegistrationHeight int64  `json:"registration_height"`
}

func (msg *QueryGuardianSBTResponse) Reset() {
	*msg = QueryGuardianSBTResponse{}
}

func (msg *QueryGuardianSBTResponse) String() string {
	return msg.SbtId
}

func (msg *QueryGuardianSBTResponse) ProtoMessage() {}

// Custom registration for gRPC service router
func RegisterQueryServer(s *grpc.Server, srv QueryServer) {
	s.RegisterService(&QueryServiceDesc, srv)
}

// QueryServiceDesc is the exported gRPC service descriptor for query messages
var QueryServiceDesc = grpc.ServiceDesc{
	ServiceName: "aeterna.guardian.v1.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GuardianSBT",
			Handler:    _Query_GuardianSBT_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "aeterna/guardian/v1/query.proto",
}

func _Query_GuardianSBT_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryGuardianSBTRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).GuardianSBT(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/aeterna.guardian.v1.Query/GuardianSBT",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).GuardianSBT(ctx, req.(*QueryGuardianSBTRequest))
	}
	return interceptor(ctx, in, info, handler)
}
