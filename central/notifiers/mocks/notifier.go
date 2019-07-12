// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stackrox/rox/central/notifiers (interfaces: Notifier)

// Package mocks is a generated GoMock package.
package mocks

import (
	gomock "github.com/golang/mock/gomock"
	storage "github.com/stackrox/rox/generated/storage"
	reflect "reflect"
)

// MockNotifier is a mock of Notifier interface
type MockNotifier struct {
	ctrl     *gomock.Controller
	recorder *MockNotifierMockRecorder
}

// MockNotifierMockRecorder is the mock recorder for MockNotifier
type MockNotifierMockRecorder struct {
	mock *MockNotifier
}

// NewMockNotifier creates a new mock instance
func NewMockNotifier(ctrl *gomock.Controller) *MockNotifier {
	mock := &MockNotifier{ctrl: ctrl}
	mock.recorder = &MockNotifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNotifier) EXPECT() *MockNotifierMockRecorder {
	return m.recorder
}

// ProtoNotifier mocks base method
func (m *MockNotifier) ProtoNotifier() *storage.Notifier {
	ret := m.ctrl.Call(m, "ProtoNotifier")
	ret0, _ := ret[0].(*storage.Notifier)
	return ret0
}

// ProtoNotifier indicates an expected call of ProtoNotifier
func (mr *MockNotifierMockRecorder) ProtoNotifier() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProtoNotifier", reflect.TypeOf((*MockNotifier)(nil).ProtoNotifier))
}

// Test mocks base method
func (m *MockNotifier) Test() error {
	ret := m.ctrl.Call(m, "Test")
	ret0, _ := ret[0].(error)
	return ret0
}

// Test indicates an expected call of Test
func (mr *MockNotifierMockRecorder) Test() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Test", reflect.TypeOf((*MockNotifier)(nil).Test))
}
