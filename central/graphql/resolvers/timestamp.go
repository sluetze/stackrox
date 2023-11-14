package resolvers

import (
	"github.com/graph-gophers/graphql-go"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func timestamp(ts *types.Timestamp) (*graphql.Time, error) {
	if ts == nil {
		return nil, nil
	}
	t, err := types.TimestampFromProto(ts)
	return &graphql.Time{Time: t}, err
}
