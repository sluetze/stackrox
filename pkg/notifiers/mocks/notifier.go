// Code generated by MockGen. DO NOT EDIT.
// Source: notifier.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/notifier.go -source notifier.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	storage "github.com/stackrox/rox/generated/storage"
	gomock "go.uber.org/mock/gomock"
)

// MockNotifier is a mock of Notifier interface.
type MockNotifier struct {
	ctrl     *gomock.Controller
	recorder *MockNotifierMockRecorder
}

// MockNotifierMockRecorder is the mock recorder for MockNotifier.
type MockNotifierMockRecorder struct {
	mock *MockNotifier
}

// NewMockNotifier creates a new mock instance.
func NewMockNotifier(ctrl *gomock.Controller) *MockNotifier {
	mock := &MockNotifier{ctrl: ctrl}
	mock.recorder = &MockNotifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNotifier) EXPECT() *MockNotifierMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockNotifier) Close(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockNotifierMockRecorder) Close(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockNotifier)(nil).Close), arg0)
}

// ProtoNotifier mocks base method.
func (m *MockNotifier) ProtoNotifier() *storage.Notifier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProtoNotifier")
	ret0, _ := ret[0].(*storage.Notifier)
	return ret0
}

// ProtoNotifier indicates an expected call of ProtoNotifier.
func (mr *MockNotifierMockRecorder) ProtoNotifier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProtoNotifier", reflect.TypeOf((*MockNotifier)(nil).ProtoNotifier))
}

// Test mocks base method.
func (m *MockNotifier) Test(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Test", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Test indicates an expected call of Test.
func (mr *MockNotifierMockRecorder) Test(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Test", reflect.TypeOf((*MockNotifier)(nil).Test), arg0)
}
