package testutils

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/golang/mock/gomock"
)

var (
	stringTy = reflect.TypeOf("")
)

type predMatcher struct {
	desc    string
	inTy    reflect.Type
	outTy   reflect.Type
	checker reflect.Value
}

// PredMatcher returns a gomock matcher that applies the given checker (which must be a unary function with a bool return
// value) to its argument.
func PredMatcher(desc string, checker interface{}) gomock.Matcher {
	ty := reflect.TypeOf(checker)

	if ty.Kind() != reflect.Func {
		panic("predicate matcher requires a function argument")
	}

	if ty.NumIn() != 1 {
		panic("function for predicate matcher must have exactly one input parameter")
	}

	if ty.NumOut() != 1 {
		panic("function for predicate matcher must have exactly one output paramer")
	}

	outTy := ty.Out(0)
	if outTy.Kind() != reflect.Bool {
		panic("function for predicate matcher must have a boolean return value")
	}

	return predMatcher{
		desc:    desc,
		inTy:    ty.In(0),
		checker: reflect.ValueOf(checker),
	}
}

func (p predMatcher) String() string {
	return p.desc
}

func (p predMatcher) Matches(x interface{}) bool {
	v := reflect.ValueOf(x)
	if !v.Type().AssignableTo(p.inTy) {
		return false
	}
	out := p.checker.Call([]reflect.Value{v})
	return out[0].Bool()
}

// StringTestMatcher returns a matcher with the given description and applying the given stringTest function
// on the argument and the specified secondArg.
func StringTestMatcher(desc string, stringTest func(string, string) bool, secondArg string) gomock.Matcher {
	return stringTestMatcher{
		desc:     desc,
		testFunc: func(s string) bool { return stringTest(s, secondArg) },
	}
}

// ContainsStringMatcher returns a matcher that tests if the argument contains the given substring.
func ContainsStringMatcher(substr string) gomock.Matcher {
	return StringTestMatcher(fmt.Sprintf("argument contains string %q", substr), strings.Contains, substr)
}

type stringTestMatcher struct {
	desc     string
	testFunc func(string) bool
}

func (m stringTestMatcher) String() string {
	return m.desc
}

func (m stringTestMatcher) Matches(x interface{}) bool {
	v := reflect.ValueOf(x)
	if v.Kind() == reflect.String {
		return m.testFunc(v.String())
	}
	if v.Type().ConvertibleTo(stringTy) {
		return m.testFunc(v.Convert(stringTy).String())
	}
	return false
}
