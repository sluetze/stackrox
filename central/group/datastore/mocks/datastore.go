// Code generated by MockGen. DO NOT EDIT.
// Source: datastore.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/datastore.go -source datastore.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	storage "github.com/stackrox/rox/generated/storage"
	gomock "go.uber.org/mock/gomock"
)

// MockDataStore is a mock of DataStore interface.
type MockDataStore struct {
	ctrl     *gomock.Controller
	recorder *MockDataStoreMockRecorder
}

// MockDataStoreMockRecorder is the mock recorder for MockDataStore.
type MockDataStoreMockRecorder struct {
	mock *MockDataStore
}

// NewMockDataStore creates a new mock instance.
func NewMockDataStore(ctrl *gomock.Controller) *MockDataStore {
	mock := &MockDataStore{ctrl: ctrl}
	mock.recorder = &MockDataStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDataStore) EXPECT() *MockDataStoreMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockDataStore) Add(ctx context.Context, group *storage.Group) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", ctx, group)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockDataStoreMockRecorder) Add(ctx, group any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockDataStore)(nil).Add), ctx, group)
}

// Get mocks base method.
func (m *MockDataStore) Get(ctx context.Context, props *storage.GroupProperties) (*storage.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, props)
	ret0, _ := ret[0].(*storage.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockDataStoreMockRecorder) Get(ctx, props any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockDataStore)(nil).Get), ctx, props)
}

// GetAll mocks base method.
func (m *MockDataStore) GetAll(ctx context.Context) ([]*storage.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAll", ctx)
	ret0, _ := ret[0].([]*storage.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAll indicates an expected call of GetAll.
func (mr *MockDataStoreMockRecorder) GetAll(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAll", reflect.TypeOf((*MockDataStore)(nil).GetAll), ctx)
}

// GetFiltered mocks base method.
func (m *MockDataStore) GetFiltered(ctx context.Context, filter func(*storage.Group) bool) ([]*storage.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFiltered", ctx, filter)
	ret0, _ := ret[0].([]*storage.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFiltered indicates an expected call of GetFiltered.
func (mr *MockDataStoreMockRecorder) GetFiltered(ctx, filter any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFiltered", reflect.TypeOf((*MockDataStore)(nil).GetFiltered), ctx, filter)
}

// Mutate mocks base method.
func (m *MockDataStore) Mutate(ctx context.Context, remove, update, add []*storage.Group, force bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Mutate", ctx, remove, update, add, force)
	ret0, _ := ret[0].(error)
	return ret0
}

// Mutate indicates an expected call of Mutate.
func (mr *MockDataStoreMockRecorder) Mutate(ctx, remove, update, add, force any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Mutate", reflect.TypeOf((*MockDataStore)(nil).Mutate), ctx, remove, update, add, force)
}

// Remove mocks base method.
func (m *MockDataStore) Remove(ctx context.Context, props *storage.GroupProperties, force bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", ctx, props, force)
	ret0, _ := ret[0].(error)
	return ret0
}

// Remove indicates an expected call of Remove.
func (mr *MockDataStoreMockRecorder) Remove(ctx, props, force any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockDataStore)(nil).Remove), ctx, props, force)
}

// RemoveAllWithAuthProviderID mocks base method.
func (m *MockDataStore) RemoveAllWithAuthProviderID(ctx context.Context, authProviderID string, force bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveAllWithAuthProviderID", ctx, authProviderID, force)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveAllWithAuthProviderID indicates an expected call of RemoveAllWithAuthProviderID.
func (mr *MockDataStoreMockRecorder) RemoveAllWithAuthProviderID(ctx, authProviderID, force any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveAllWithAuthProviderID", reflect.TypeOf((*MockDataStore)(nil).RemoveAllWithAuthProviderID), ctx, authProviderID, force)
}

// RemoveAllWithEmptyProperties mocks base method.
func (m *MockDataStore) RemoveAllWithEmptyProperties(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveAllWithEmptyProperties", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveAllWithEmptyProperties indicates an expected call of RemoveAllWithEmptyProperties.
func (mr *MockDataStoreMockRecorder) RemoveAllWithEmptyProperties(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveAllWithEmptyProperties", reflect.TypeOf((*MockDataStore)(nil).RemoveAllWithEmptyProperties), ctx)
}

// Update mocks base method.
func (m *MockDataStore) Update(ctx context.Context, group *storage.Group, force bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, group, force)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockDataStoreMockRecorder) Update(ctx, group, force any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockDataStore)(nil).Update), ctx, group, force)
}

// Upsert mocks base method.
func (m *MockDataStore) Upsert(ctx context.Context, group *storage.Group) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Upsert", ctx, group)
	ret0, _ := ret[0].(error)
	return ret0
}

// Upsert indicates an expected call of Upsert.
func (mr *MockDataStoreMockRecorder) Upsert(ctx, group any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Upsert", reflect.TypeOf((*MockDataStore)(nil).Upsert), ctx, group)
}

// Walk mocks base method.
func (m *MockDataStore) Walk(ctx context.Context, authProviderID string, attributes map[string][]string) ([]*storage.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Walk", ctx, authProviderID, attributes)
	ret0, _ := ret[0].([]*storage.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Walk indicates an expected call of Walk.
func (mr *MockDataStoreMockRecorder) Walk(ctx, authProviderID, attributes any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Walk", reflect.TypeOf((*MockDataStore)(nil).Walk), ctx, authProviderID, attributes)
}
