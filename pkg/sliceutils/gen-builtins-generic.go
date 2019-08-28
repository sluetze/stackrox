// Code generated by genny. DO NOT EDIT.
// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/mauricelam/genny

package sliceutils

// BoolDiff returns, given two sorted bool slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func BoolDiff(a, b []bool, lessFunc func(a, b bool) bool) (aOnly, bOnly []bool) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// BoolFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func BoolFind(slice []bool, elem bool) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatBoolSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatBoolSlices(slices ...[]bool) []bool {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]bool, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// BoolUnique returns a new slice that contains only the first occurrence of each element in slice.
func BoolUnique(slice []bool) []bool {
	result := make([]bool, 0, len(slice))
	seen := make(map[bool]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// ByteDiff returns, given two sorted byte slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func ByteDiff(a, b []byte, lessFunc func(a, b byte) bool) (aOnly, bOnly []byte) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// ByteFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func ByteFind(slice []byte, elem byte) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatByteSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatByteSlices(slices ...[]byte) []byte {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]byte, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// ByteUnique returns a new slice that contains only the first occurrence of each element in slice.
func ByteUnique(slice []byte) []byte {
	result := make([]byte, 0, len(slice))
	seen := make(map[byte]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Complex128Diff returns, given two sorted complex128 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Complex128Diff(a, b []complex128, lessFunc func(a, b complex128) bool) (aOnly, bOnly []complex128) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Complex128Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Complex128Find(slice []complex128, elem complex128) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatComplex128Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatComplex128Slices(slices ...[]complex128) []complex128 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]complex128, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Complex128Unique returns a new slice that contains only the first occurrence of each element in slice.
func Complex128Unique(slice []complex128) []complex128 {
	result := make([]complex128, 0, len(slice))
	seen := make(map[complex128]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Complex64Diff returns, given two sorted complex64 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Complex64Diff(a, b []complex64, lessFunc func(a, b complex64) bool) (aOnly, bOnly []complex64) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Complex64Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Complex64Find(slice []complex64, elem complex64) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatComplex64Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatComplex64Slices(slices ...[]complex64) []complex64 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]complex64, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Complex64Unique returns a new slice that contains only the first occurrence of each element in slice.
func Complex64Unique(slice []complex64) []complex64 {
	result := make([]complex64, 0, len(slice))
	seen := make(map[complex64]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// ErrorDiff returns, given two sorted error slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func ErrorDiff(a, b []error, lessFunc func(a, b error) bool) (aOnly, bOnly []error) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// ErrorFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func ErrorFind(slice []error, elem error) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatErrorSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatErrorSlices(slices ...[]error) []error {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]error, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// ErrorUnique returns a new slice that contains only the first occurrence of each element in slice.
func ErrorUnique(slice []error) []error {
	result := make([]error, 0, len(slice))
	seen := make(map[error]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Float32Diff returns, given two sorted float32 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Float32Diff(a, b []float32, lessFunc func(a, b float32) bool) (aOnly, bOnly []float32) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Float32Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Float32Find(slice []float32, elem float32) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatFloat32Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatFloat32Slices(slices ...[]float32) []float32 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]float32, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Float32Unique returns a new slice that contains only the first occurrence of each element in slice.
func Float32Unique(slice []float32) []float32 {
	result := make([]float32, 0, len(slice))
	seen := make(map[float32]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Float64Diff returns, given two sorted float64 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Float64Diff(a, b []float64, lessFunc func(a, b float64) bool) (aOnly, bOnly []float64) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Float64Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Float64Find(slice []float64, elem float64) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatFloat64Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatFloat64Slices(slices ...[]float64) []float64 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]float64, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Float64Unique returns a new slice that contains only the first occurrence of each element in slice.
func Float64Unique(slice []float64) []float64 {
	result := make([]float64, 0, len(slice))
	seen := make(map[float64]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// IntDiff returns, given two sorted int slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func IntDiff(a, b []int, lessFunc func(a, b int) bool) (aOnly, bOnly []int) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// IntFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func IntFind(slice []int, elem int) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatIntSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatIntSlices(slices ...[]int) []int {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]int, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// IntUnique returns a new slice that contains only the first occurrence of each element in slice.
func IntUnique(slice []int) []int {
	result := make([]int, 0, len(slice))
	seen := make(map[int]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Int16Diff returns, given two sorted int16 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Int16Diff(a, b []int16, lessFunc func(a, b int16) bool) (aOnly, bOnly []int16) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Int16Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Int16Find(slice []int16, elem int16) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatInt16Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatInt16Slices(slices ...[]int16) []int16 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]int16, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Int16Unique returns a new slice that contains only the first occurrence of each element in slice.
func Int16Unique(slice []int16) []int16 {
	result := make([]int16, 0, len(slice))
	seen := make(map[int16]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Int32Diff returns, given two sorted int32 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Int32Diff(a, b []int32, lessFunc func(a, b int32) bool) (aOnly, bOnly []int32) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Int32Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Int32Find(slice []int32, elem int32) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatInt32Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatInt32Slices(slices ...[]int32) []int32 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]int32, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Int32Unique returns a new slice that contains only the first occurrence of each element in slice.
func Int32Unique(slice []int32) []int32 {
	result := make([]int32, 0, len(slice))
	seen := make(map[int32]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Int64Diff returns, given two sorted int64 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Int64Diff(a, b []int64, lessFunc func(a, b int64) bool) (aOnly, bOnly []int64) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Int64Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Int64Find(slice []int64, elem int64) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatInt64Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatInt64Slices(slices ...[]int64) []int64 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]int64, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Int64Unique returns a new slice that contains only the first occurrence of each element in slice.
func Int64Unique(slice []int64) []int64 {
	result := make([]int64, 0, len(slice))
	seen := make(map[int64]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Int8Diff returns, given two sorted int8 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Int8Diff(a, b []int8, lessFunc func(a, b int8) bool) (aOnly, bOnly []int8) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Int8Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Int8Find(slice []int8, elem int8) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatInt8Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatInt8Slices(slices ...[]int8) []int8 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]int8, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Int8Unique returns a new slice that contains only the first occurrence of each element in slice.
func Int8Unique(slice []int8) []int8 {
	result := make([]int8, 0, len(slice))
	seen := make(map[int8]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// RuneDiff returns, given two sorted rune slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func RuneDiff(a, b []rune, lessFunc func(a, b rune) bool) (aOnly, bOnly []rune) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// RuneFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func RuneFind(slice []rune, elem rune) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatRuneSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatRuneSlices(slices ...[]rune) []rune {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]rune, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// RuneUnique returns a new slice that contains only the first occurrence of each element in slice.
func RuneUnique(slice []rune) []rune {
	result := make([]rune, 0, len(slice))
	seen := make(map[rune]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// StringDiff returns, given two sorted string slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func StringDiff(a, b []string, lessFunc func(a, b string) bool) (aOnly, bOnly []string) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// StringFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func StringFind(slice []string, elem string) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatStringSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatStringSlices(slices ...[]string) []string {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]string, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// StringUnique returns a new slice that contains only the first occurrence of each element in slice.
func StringUnique(slice []string) []string {
	result := make([]string, 0, len(slice))
	seen := make(map[string]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// UintDiff returns, given two sorted uint slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func UintDiff(a, b []uint, lessFunc func(a, b uint) bool) (aOnly, bOnly []uint) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// UintFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func UintFind(slice []uint, elem uint) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatUintSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatUintSlices(slices ...[]uint) []uint {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]uint, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// UintUnique returns a new slice that contains only the first occurrence of each element in slice.
func UintUnique(slice []uint) []uint {
	result := make([]uint, 0, len(slice))
	seen := make(map[uint]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Uint16Diff returns, given two sorted uint16 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Uint16Diff(a, b []uint16, lessFunc func(a, b uint16) bool) (aOnly, bOnly []uint16) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Uint16Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Uint16Find(slice []uint16, elem uint16) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatUint16Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatUint16Slices(slices ...[]uint16) []uint16 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]uint16, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Uint16Unique returns a new slice that contains only the first occurrence of each element in slice.
func Uint16Unique(slice []uint16) []uint16 {
	result := make([]uint16, 0, len(slice))
	seen := make(map[uint16]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Uint32Diff returns, given two sorted uint32 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Uint32Diff(a, b []uint32, lessFunc func(a, b uint32) bool) (aOnly, bOnly []uint32) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Uint32Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Uint32Find(slice []uint32, elem uint32) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatUint32Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatUint32Slices(slices ...[]uint32) []uint32 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]uint32, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Uint32Unique returns a new slice that contains only the first occurrence of each element in slice.
func Uint32Unique(slice []uint32) []uint32 {
	result := make([]uint32, 0, len(slice))
	seen := make(map[uint32]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Uint64Diff returns, given two sorted uint64 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Uint64Diff(a, b []uint64, lessFunc func(a, b uint64) bool) (aOnly, bOnly []uint64) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Uint64Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Uint64Find(slice []uint64, elem uint64) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatUint64Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatUint64Slices(slices ...[]uint64) []uint64 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]uint64, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Uint64Unique returns a new slice that contains only the first occurrence of each element in slice.
func Uint64Unique(slice []uint64) []uint64 {
	result := make([]uint64, 0, len(slice))
	seen := make(map[uint64]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// Uint8Diff returns, given two sorted uint8 slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func Uint8Diff(a, b []uint8, lessFunc func(a, b uint8) bool) (aOnly, bOnly []uint8) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// Uint8Find returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func Uint8Find(slice []uint8, elem uint8) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatUint8Slices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatUint8Slices(slices ...[]uint8) []uint8 {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]uint8, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// Uint8Unique returns a new slice that contains only the first occurrence of each element in slice.
func Uint8Unique(slice []uint8) []uint8 {
	result := make([]uint8, 0, len(slice))
	seen := make(map[uint8]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}

// UintptrDiff returns, given two sorted uintptr slices a and b, a slice of the elements occurring in a and b only,
// respectively.
func UintptrDiff(a, b []uintptr, lessFunc func(a, b uintptr) bool) (aOnly, bOnly []uintptr) {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if lessFunc(a[i], b[j]) {
			aOnly = append(aOnly, a[i])
			i++
		} else if lessFunc(b[j], a[i]) {
			bOnly = append(bOnly, b[j])
			j++
		} else { // a[i] and b[j] are "equal"
			i++
			j++
		}
	}

	aOnly = append(aOnly, a[i:]...)
	bOnly = append(bOnly, b[j:]...)
	return
}

// UintptrFind returns, given a slice and an element, the first index of elem in the slice, or -1 if the slice does
// not contain elem.
func UintptrFind(slice []uintptr, elem uintptr) int {
	for i, sliceElem := range slice {
		if sliceElem == elem {
			return i
		}
	}
	return -1
}

// ConcatUintptrSlices concatenates slices, returning a slice with newly allocated backing storage of the exact
// size.
func ConcatUintptrSlices(slices ...[]uintptr) []uintptr {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]uintptr, length)
	i := 0
	for _, slice := range slices {
		nextI := i + len(slice)
		copy(result[i:nextI], slice)
		i = nextI
	}
	return result
}

// UintptrUnique returns a new slice that contains only the first occurrence of each element in slice.
func UintptrUnique(slice []uintptr) []uintptr {
	result := make([]uintptr, 0, len(slice))
	seen := make(map[uintptr]struct{}, len(slice))
	for _, elem := range slice {
		if _, ok := seen[elem]; !ok {
			result = append(result, elem)
			seen[elem] = struct{}{}
		}
	}
	return result
}
