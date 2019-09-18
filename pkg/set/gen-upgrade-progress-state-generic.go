// Code generated by genny. DO NOT EDIT.
// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/mauricelam/genny

package set

import (
	"sort"

	"github.com/stackrox/rox/generated/storage"

	mapset "github.com/deckarep/golang-set"
)

// If you want to add a set for your custom type, simply add another go generate line along with the
// existing ones. If you're creating a set for a primitive type, you can follow the example of "string"
// and create the generated file in this package.
// Sometimes, you might need to create it in the same package where it is defined to avoid import cycles.
// The permission set is an example of how to do that.
// You can also specify the -imp command to specify additional imports in your generated file, if required.

// storage.UpgradeProgress_UpgradeState represents a generic type that we want to have a set of.

// StorageUpgradeProgress_UpgradeStateSet will get translated to generic sets.
// It uses mapset.Set as the underlying implementation, so it comes with a bunch
// of utility methods, and is thread-safe.
type StorageUpgradeProgress_UpgradeStateSet struct {
	underlying mapset.Set
}

// Add adds an element of type storage.UpgradeProgress_UpgradeState.
func (k StorageUpgradeProgress_UpgradeStateSet) Add(i storage.UpgradeProgress_UpgradeState) bool {
	if k.underlying == nil {
		k.underlying = mapset.NewThreadUnsafeSet()
	}

	return k.underlying.Add(i)
}

// AddAll adds all elements of type storage.UpgradeProgress_UpgradeState. The return value is true if any new element
// was added.
func (k StorageUpgradeProgress_UpgradeStateSet) AddAll(is ...storage.UpgradeProgress_UpgradeState) bool {
	if k.underlying == nil {
		k.underlying = mapset.NewThreadUnsafeSet()
	}

	added := false
	for _, i := range is {
		added = k.underlying.Add(i) || added
	}
	return added
}

// Remove removes an element of type storage.UpgradeProgress_UpgradeState.
func (k StorageUpgradeProgress_UpgradeStateSet) Remove(i storage.UpgradeProgress_UpgradeState) {
	if k.underlying != nil {
		k.underlying.Remove(i)
	}
}

// RemoveAll removes the given elements.
func (k StorageUpgradeProgress_UpgradeStateSet) RemoveAll(is ...storage.UpgradeProgress_UpgradeState) {
	if k.underlying == nil {
		return
	}
	for _, i := range is {
		k.underlying.Remove(i)
	}
}

// RemoveMatching removes all elements that match a given predicate.
func (k StorageUpgradeProgress_UpgradeStateSet) RemoveMatching(pred func(storage.UpgradeProgress_UpgradeState) bool) {
	if k.underlying == nil {
		return
	}
	for _, elem := range k.AsSlice() {
		if pred(elem) {
			k.underlying.Remove(elem)
		}
	}
}

// Contains returns whether the set contains an element of type storage.UpgradeProgress_UpgradeState.
func (k StorageUpgradeProgress_UpgradeStateSet) Contains(i storage.UpgradeProgress_UpgradeState) bool {
	if k.underlying != nil {
		return k.underlying.Contains(i)
	}
	return false
}

// Cardinality returns the number of elements in the set.
func (k StorageUpgradeProgress_UpgradeStateSet) Cardinality() int {
	if k.underlying != nil {
		return k.underlying.Cardinality()
	}
	return 0
}

// Difference returns a new set with all elements of k not in other.
func (k StorageUpgradeProgress_UpgradeStateSet) Difference(other StorageUpgradeProgress_UpgradeStateSet) StorageUpgradeProgress_UpgradeStateSet {
	if k.underlying == nil {
		return StorageUpgradeProgress_UpgradeStateSet{underlying: other.underlying}
	} else if other.underlying == nil {
		return StorageUpgradeProgress_UpgradeStateSet{underlying: k.underlying}
	}

	return StorageUpgradeProgress_UpgradeStateSet{underlying: k.underlying.Difference(other.underlying)}
}

// Intersect returns a new set with the intersection of the members of both sets.
func (k StorageUpgradeProgress_UpgradeStateSet) Intersect(other StorageUpgradeProgress_UpgradeStateSet) StorageUpgradeProgress_UpgradeStateSet {
	if k.underlying != nil && other.underlying != nil {
		return StorageUpgradeProgress_UpgradeStateSet{underlying: k.underlying.Intersect(other.underlying)}
	}
	return StorageUpgradeProgress_UpgradeStateSet{}
}

// Union returns a new set with the union of the members of both sets.
func (k StorageUpgradeProgress_UpgradeStateSet) Union(other StorageUpgradeProgress_UpgradeStateSet) StorageUpgradeProgress_UpgradeStateSet {
	if k.underlying == nil {
		return StorageUpgradeProgress_UpgradeStateSet{underlying: other.underlying}
	} else if other.underlying == nil {
		return StorageUpgradeProgress_UpgradeStateSet{underlying: k.underlying}
	}

	return StorageUpgradeProgress_UpgradeStateSet{underlying: k.underlying.Union(other.underlying)}
}

// Equal returns a bool if the sets are equal
func (k StorageUpgradeProgress_UpgradeStateSet) Equal(other StorageUpgradeProgress_UpgradeStateSet) bool {
	if k.underlying == nil && other.underlying == nil {
		return true
	}
	if k.underlying == nil || other.underlying == nil {
		return false
	}
	return k.underlying.Equal(other.underlying)
}

// AsSlice returns a slice of the elements in the set. The order is unspecified.
func (k StorageUpgradeProgress_UpgradeStateSet) AsSlice() []storage.UpgradeProgress_UpgradeState {
	if k.underlying == nil {
		return nil
	}
	elems := make([]storage.UpgradeProgress_UpgradeState, 0, k.Cardinality())
	for elem := range k.underlying.Iter() {
		elems = append(elems, elem.(storage.UpgradeProgress_UpgradeState))
	}
	return elems
}

// AsSortedSlice returns a slice of the elements in the set, sorted using the passed less function.
func (k StorageUpgradeProgress_UpgradeStateSet) AsSortedSlice(less func(i, j storage.UpgradeProgress_UpgradeState) bool) []storage.UpgradeProgress_UpgradeState {
	slice := k.AsSlice()
	if len(slice) < 2 {
		return slice
	}
	// Since we're generating the code, we might as well use sort.Sort
	// and avoid paying the reflection penalty of sort.Slice.
	sortable := &sortableStorageUpgradeProgress_UpgradeStateSlice{slice: slice, less: less}
	sort.Sort(sortable)
	return sortable.slice
}

// IsInitialized returns whether the set has been initialized
func (k StorageUpgradeProgress_UpgradeStateSet) IsInitialized() bool {
	return k.underlying != nil
}

// Iter returns a range of elements you can iterate over.
// Note that in most cases, this is actually slower than pulling out a slice
// and ranging over that.
// NOTE THAT YOU MUST DRAIN THE RETURNED CHANNEL, OR THE SET WILL BE DEADLOCKED FOREVER.
func (k StorageUpgradeProgress_UpgradeStateSet) Iter() <-chan storage.UpgradeProgress_UpgradeState {
	ch := make(chan storage.UpgradeProgress_UpgradeState)
	if k.underlying != nil {
		go func() {
			for elem := range k.underlying.Iter() {
				ch <- elem.(storage.UpgradeProgress_UpgradeState)
			}
			close(ch)
		}()
	} else {
		close(ch)
	}
	return ch
}

// Clear empties the set
func (k StorageUpgradeProgress_UpgradeStateSet) Clear() {
	if k.underlying == nil {
		return
	}
	k.underlying.Clear()
}

// Freeze returns a new, frozen version of the set.
func (k StorageUpgradeProgress_UpgradeStateSet) Freeze() FrozenStorageUpgradeProgress_UpgradeStateSet {
	return NewFrozenStorageUpgradeProgress_UpgradeStateSet(k.AsSlice()...)
}

// NewStorageUpgradeProgress_UpgradeStateSet returns a new thread unsafe set with the given key type.
func NewStorageUpgradeProgress_UpgradeStateSet(initial ...storage.UpgradeProgress_UpgradeState) StorageUpgradeProgress_UpgradeStateSet {
	k := StorageUpgradeProgress_UpgradeStateSet{underlying: mapset.NewThreadUnsafeSet()}
	for _, elem := range initial {
		k.Add(elem)
	}
	return k
}

// NewThreadSafeStorageUpgradeProgress_UpgradeStateSet returns a new thread safe set
func NewThreadSafeStorageUpgradeProgress_UpgradeStateSet(initial ...storage.UpgradeProgress_UpgradeState) StorageUpgradeProgress_UpgradeStateSet {
	k := StorageUpgradeProgress_UpgradeStateSet{underlying: mapset.NewSet()}
	for _, elem := range initial {
		k.Add(elem)
	}
	return k
}

type sortableStorageUpgradeProgress_UpgradeStateSlice struct {
	slice []storage.UpgradeProgress_UpgradeState
	less  func(i, j storage.UpgradeProgress_UpgradeState) bool
}

func (s *sortableStorageUpgradeProgress_UpgradeStateSlice) Len() int {
	return len(s.slice)
}

func (s *sortableStorageUpgradeProgress_UpgradeStateSlice) Less(i, j int) bool {
	return s.less(s.slice[i], s.slice[j])
}

func (s *sortableStorageUpgradeProgress_UpgradeStateSlice) Swap(i, j int) {
	s.slice[j], s.slice[i] = s.slice[i], s.slice[j]
}

// A FrozenStorageUpgradeProgress_UpgradeStateSet is a frozen set of storage.UpgradeProgress_UpgradeState elements, which
// cannot be modified after creation. This allows users to use it as if it were
// a "const" data structure, and also makes it slightly more optimal since
// we don't have to lock accesses to it.
type FrozenStorageUpgradeProgress_UpgradeStateSet struct {
	underlying map[storage.UpgradeProgress_UpgradeState]struct{}
}

// NewFrozenStorageUpgradeProgress_UpgradeStateSetFromChan returns a new frozen set from the provided channel.
// It drains the channel.
// This can be useful to avoid unnecessary slice allocations.
func NewFrozenStorageUpgradeProgress_UpgradeStateSetFromChan(elementC <-chan storage.UpgradeProgress_UpgradeState) FrozenStorageUpgradeProgress_UpgradeStateSet {
	underlying := make(map[storage.UpgradeProgress_UpgradeState]struct{})
	for elem := range elementC {
		underlying[elem] = struct{}{}
	}
	return FrozenStorageUpgradeProgress_UpgradeStateSet{
		underlying: underlying,
	}
}

// NewFrozenStorageUpgradeProgress_UpgradeStateSet returns a new frozen set with the provided elements.
func NewFrozenStorageUpgradeProgress_UpgradeStateSet(elements ...storage.UpgradeProgress_UpgradeState) FrozenStorageUpgradeProgress_UpgradeStateSet {
	underlying := make(map[storage.UpgradeProgress_UpgradeState]struct{}, len(elements))
	for _, elem := range elements {
		underlying[elem] = struct{}{}
	}
	return FrozenStorageUpgradeProgress_UpgradeStateSet{
		underlying: underlying,
	}
}

// Contains returns whether the set contains the element.
func (k FrozenStorageUpgradeProgress_UpgradeStateSet) Contains(elem storage.UpgradeProgress_UpgradeState) bool {
	_, ok := k.underlying[elem]
	return ok
}

// Cardinality returns the cardinality of the set.
func (k FrozenStorageUpgradeProgress_UpgradeStateSet) Cardinality() int {
	return len(k.underlying)
}

// AsSlice returns the elements of the set. The order is unspecified.
func (k FrozenStorageUpgradeProgress_UpgradeStateSet) AsSlice() []storage.UpgradeProgress_UpgradeState {
	if len(k.underlying) == 0 {
		return nil
	}
	slice := make([]storage.UpgradeProgress_UpgradeState, 0, len(k.underlying))
	for elem := range k.underlying {
		slice = append(slice, elem)
	}
	return slice
}

// AsSortedSlice returns the elements of the set as a sorted slice.
func (k FrozenStorageUpgradeProgress_UpgradeStateSet) AsSortedSlice(less func(i, j storage.UpgradeProgress_UpgradeState) bool) []storage.UpgradeProgress_UpgradeState {
	slice := k.AsSlice()
	if len(slice) < 2 {
		return slice
	}
	// Since we're generating the code, we might as well use sort.Sort
	// and avoid paying the reflection penalty of sort.Slice.
	sortable := &sortableStorageUpgradeProgress_UpgradeStateSlice{slice: slice, less: less}
	sort.Sort(sortable)
	return sortable.slice
}
