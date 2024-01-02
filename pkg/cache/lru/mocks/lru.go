// Code generated by MockGen. DO NOT EDIT.
// Source: lru.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/lru.go -source lru.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockLRU is a mock of LRU interface.
type MockLRU[K comparable, V any] struct {
	ctrl     *gomock.Controller
	recorder *MockLRUMockRecorder[K, V]
}

// MockLRUMockRecorder is the mock recorder for MockLRU.
type MockLRUMockRecorder[K comparable, V any] struct {
	mock *MockLRU[K, V]
}

// NewMockLRU creates a new mock instance.
func NewMockLRU[K comparable, V any](ctrl *gomock.Controller) *MockLRU[K, V] {
	mock := &MockLRU[K, V]{ctrl: ctrl}
	mock.recorder = &MockLRUMockRecorder[K, V]{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLRU[K, V]) EXPECT() *MockLRUMockRecorder[K, V] {
	return m.recorder
}

// Add mocks base method.
func (m *MockLRU[K, V]) Add(key K, value V) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", key, value)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockLRUMockRecorder[K, V]) Add(key, value any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockLRU[K, V])(nil).Add), key, value)
}

// Get mocks base method.
func (m *MockLRU[K, V]) Get(key K) (V, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", key)
	ret0, _ := ret[0].(V)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockLRUMockRecorder[K, V]) Get(key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockLRU[K, V])(nil).Get), key)
}

// Keys mocks base method.
func (m *MockLRU[K, V]) Keys() []K {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Keys")
	ret0, _ := ret[0].([]K)
	return ret0
}

// Keys indicates an expected call of Keys.
func (mr *MockLRUMockRecorder[K, V]) Keys() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Keys", reflect.TypeOf((*MockLRU[K, V])(nil).Keys))
}

// Peek mocks base method.
func (m *MockLRU[K, V]) Peek(key K) (V, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Peek", key)
	ret0, _ := ret[0].(V)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Peek indicates an expected call of Peek.
func (mr *MockLRUMockRecorder[K, V]) Peek(key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Peek", reflect.TypeOf((*MockLRU[K, V])(nil).Peek), key)
}

// Purge mocks base method.
func (m *MockLRU[K, V]) Purge() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Purge")
}

// Purge indicates an expected call of Purge.
func (mr *MockLRUMockRecorder[K, V]) Purge() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Purge", reflect.TypeOf((*MockLRU[K, V])(nil).Purge))
}

// Remove mocks base method.
func (m *MockLRU[K, V]) Remove(key K) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", key)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Remove indicates an expected call of Remove.
func (mr *MockLRUMockRecorder[K, V]) Remove(key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockLRU[K, V])(nil).Remove), key)
}
