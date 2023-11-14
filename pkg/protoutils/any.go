package protoutils

import (
	proto "github.com/CrowdStrike/csproto"
	golangProto "github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MarshalAny correctly marshals a proto message into an Any
// which is required because of our use of gogo and golang proto
// TODO(cgorman) Resolve this by correctly implementing the other proto
// pieces
func MarshalAny(msg proto.Message) (*types.Any, error) {
	a, err := types.MarshalAny(msg)
	if err != nil {
		return nil, err
	}
	a.TypeUrl = golangProto.MessageName(msg)
	return a, nil
}
