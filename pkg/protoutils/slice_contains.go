package protoutils

import (
	"github.com/gogo/protobuf/proto"
	"github.com/stackrox/rox/pkg/protocompat"
)

// SliceContains returns whether the given slice of proto objects contains the given proto object.
func SliceContains[T proto.Message](msg T, slice []T) bool {
	for _, elem := range slice {
		if protocompat.Equal(elem, msg) {
			return true
		}
	}
	return false
}
