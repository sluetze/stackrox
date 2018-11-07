// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stackrox/rox/central/notifier/store (interfaces: Store)

// Package mocks is a generated GoMock package.
package mocks

import (
	gomock "github.com/golang/mock/gomock"
	v1 "github.com/stackrox/rox/generated/api/v1"
	reflect "reflect"
)

// MockStore is a mock of Store interface
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// AddNotifier mocks base method
func (m *MockStore) AddNotifier(arg0 *v1.Notifier) (string, error) {
	ret := m.ctrl.Call(m, "AddNotifier", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddNotifier indicates an expected call of AddNotifier
func (mr *MockStoreMockRecorder) AddNotifier(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddNotifier", reflect.TypeOf((*MockStore)(nil).AddNotifier), arg0)
}

// GetNotifier mocks base method
func (m *MockStore) GetNotifier(arg0 string) (*v1.Notifier, bool, error) {
	ret := m.ctrl.Call(m, "GetNotifier", arg0)
	ret0, _ := ret[0].(*v1.Notifier)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetNotifier indicates an expected call of GetNotifier
func (mr *MockStoreMockRecorder) GetNotifier(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNotifier", reflect.TypeOf((*MockStore)(nil).GetNotifier), arg0)
}

// GetNotifiers mocks base method
func (m *MockStore) GetNotifiers(arg0 *v1.GetNotifiersRequest) ([]*v1.Notifier, error) {
	ret := m.ctrl.Call(m, "GetNotifiers", arg0)
	ret0, _ := ret[0].([]*v1.Notifier)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNotifiers indicates an expected call of GetNotifiers
func (mr *MockStoreMockRecorder) GetNotifiers(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNotifiers", reflect.TypeOf((*MockStore)(nil).GetNotifiers), arg0)
}

// RemoveNotifier mocks base method
func (m *MockStore) RemoveNotifier(arg0 string) error {
	ret := m.ctrl.Call(m, "RemoveNotifier", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveNotifier indicates an expected call of RemoveNotifier
func (mr *MockStoreMockRecorder) RemoveNotifier(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveNotifier", reflect.TypeOf((*MockStore)(nil).RemoveNotifier), arg0)
}

// UpdateNotifier mocks base method
func (m *MockStore) UpdateNotifier(arg0 *v1.Notifier) error {
	ret := m.ctrl.Call(m, "UpdateNotifier", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateNotifier indicates an expected call of UpdateNotifier
func (mr *MockStoreMockRecorder) UpdateNotifier(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateNotifier", reflect.TypeOf((*MockStore)(nil).UpdateNotifier), arg0)
}
