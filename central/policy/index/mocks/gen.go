// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stackrox/rox/central/policy/index (interfaces: Indexer)

// Package mocks is a generated GoMock package.
package mocks

import (
	gomock "github.com/golang/mock/gomock"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	reflect "reflect"
)

// MockIndexer is a mock of Indexer interface
type MockIndexer struct {
	ctrl     *gomock.Controller
	recorder *MockIndexerMockRecorder
}

// MockIndexerMockRecorder is the mock recorder for MockIndexer
type MockIndexerMockRecorder struct {
	mock *MockIndexer
}

// NewMockIndexer creates a new mock instance
func NewMockIndexer(ctrl *gomock.Controller) *MockIndexer {
	mock := &MockIndexer{ctrl: ctrl}
	mock.recorder = &MockIndexerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockIndexer) EXPECT() *MockIndexerMockRecorder {
	return m.recorder
}

// AddPolicies mocks base method
func (m *MockIndexer) AddPolicies(arg0 []*storage.Policy) error {
	ret := m.ctrl.Call(m, "AddPolicies", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddPolicies indicates an expected call of AddPolicies
func (mr *MockIndexerMockRecorder) AddPolicies(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddPolicies", reflect.TypeOf((*MockIndexer)(nil).AddPolicies), arg0)
}

// AddPolicy mocks base method
func (m *MockIndexer) AddPolicy(arg0 *storage.Policy) error {
	ret := m.ctrl.Call(m, "AddPolicy", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddPolicy indicates an expected call of AddPolicy
func (mr *MockIndexerMockRecorder) AddPolicy(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddPolicy", reflect.TypeOf((*MockIndexer)(nil).AddPolicy), arg0)
}

// DeletePolicies mocks base method
func (m *MockIndexer) DeletePolicies(arg0 []string) error {
	ret := m.ctrl.Call(m, "DeletePolicies", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeletePolicies indicates an expected call of DeletePolicies
func (mr *MockIndexerMockRecorder) DeletePolicies(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePolicies", reflect.TypeOf((*MockIndexer)(nil).DeletePolicies), arg0)
}

// DeletePolicy mocks base method
func (m *MockIndexer) DeletePolicy(arg0 string) error {
	ret := m.ctrl.Call(m, "DeletePolicy", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeletePolicy indicates an expected call of DeletePolicy
func (mr *MockIndexerMockRecorder) DeletePolicy(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePolicy", reflect.TypeOf((*MockIndexer)(nil).DeletePolicy), arg0)
}

// GetTxnCount mocks base method
func (m *MockIndexer) GetTxnCount() uint64 {
	ret := m.ctrl.Call(m, "GetTxnCount")
	ret0, _ := ret[0].(uint64)
	return ret0
}

// GetTxnCount indicates an expected call of GetTxnCount
func (mr *MockIndexerMockRecorder) GetTxnCount() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTxnCount", reflect.TypeOf((*MockIndexer)(nil).GetTxnCount))
}

// ResetIndex mocks base method
func (m *MockIndexer) ResetIndex() error {
	ret := m.ctrl.Call(m, "ResetIndex")
	ret0, _ := ret[0].(error)
	return ret0
}

// ResetIndex indicates an expected call of ResetIndex
func (mr *MockIndexerMockRecorder) ResetIndex() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResetIndex", reflect.TypeOf((*MockIndexer)(nil).ResetIndex))
}

// Search mocks base method
func (m *MockIndexer) Search(arg0 *v1.Query, arg1 ...blevesearch.SearchOption) ([]search.Result, error) {
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Search", varargs...)
	ret0, _ := ret[0].([]search.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Search indicates an expected call of Search
func (mr *MockIndexerMockRecorder) Search(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Search", reflect.TypeOf((*MockIndexer)(nil).Search), varargs...)
}

// SetTxnCount mocks base method
func (m *MockIndexer) SetTxnCount(arg0 uint64) error {
	ret := m.ctrl.Call(m, "SetTxnCount", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetTxnCount indicates an expected call of SetTxnCount
func (mr *MockIndexerMockRecorder) SetTxnCount(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTxnCount", reflect.TypeOf((*MockIndexer)(nil).SetTxnCount), arg0)
}
