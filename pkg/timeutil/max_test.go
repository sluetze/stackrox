package timeutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMaxProtoValid(t *testing.T) {
	t.Parallel()

	tsProto, err := types.TimestampProto(MaxProtoValid)
	assert.NoError(t, err)

	ts, err := types.TimestampFromProto(tsProto)
	assert.NoError(t, err)
	assert.Equal(t, MaxProtoValid, ts)
}
