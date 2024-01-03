package protoutils

import (
	"github.com/gogo/protobuf/proto"
	"github.com/stackrox/rox/pkg/protocompat"
)

// SlicesEqual returns whether the given two slices of proto objects have equal values.
func SlicesEqual[T proto.Message](first, second []T) bool {
	if len(first) != len(second) {
		return false
	}
	for i, firstElem := range first {
		secondElem := second[i]
		if !protocompat.Equal(firstElem, secondElem) {
			return false
		}
	}
	return true
}
