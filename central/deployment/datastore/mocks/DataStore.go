// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"
import v1 "github.com/stackrox/rox/generated/api/v1"

// DataStore is an autogenerated mock type for the DataStore type
type DataStore struct {
	mock.Mock
}

// CountDeployments provides a mock function with given fields:
func (_m *DataStore) CountDeployments() (int, error) {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDeployment provides a mock function with given fields: id
func (_m *DataStore) GetDeployment(id string) (*v1.Deployment, bool, error) {
	ret := _m.Called(id)

	var r0 *v1.Deployment
	if rf, ok := ret.Get(0).(func(string) *v1.Deployment); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v1.Deployment)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(string) error); ok {
		r2 = rf(id)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// GetDeployments provides a mock function with given fields:
func (_m *DataStore) GetDeployments() ([]*v1.Deployment, error) {
	ret := _m.Called()

	var r0 []*v1.Deployment
	if rf, ok := ret.Get(0).(func() []*v1.Deployment); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*v1.Deployment)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListDeployment provides a mock function with given fields: id
func (_m *DataStore) ListDeployment(id string) (*v1.ListDeployment, bool, error) {
	ret := _m.Called(id)

	var r0 *v1.ListDeployment
	if rf, ok := ret.Get(0).(func(string) *v1.ListDeployment); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v1.ListDeployment)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Get(1).(bool)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(string) error); ok {
		r2 = rf(id)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// ListDeployments provides a mock function with given fields:
func (_m *DataStore) ListDeployments() ([]*v1.ListDeployment, error) {
	ret := _m.Called()

	var r0 []*v1.ListDeployment
	if rf, ok := ret.Get(0).(func() []*v1.ListDeployment); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*v1.ListDeployment)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveDeployment provides a mock function with given fields: id
func (_m *DataStore) RemoveDeployment(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SearchDeployments provides a mock function with given fields: request
func (_m *DataStore) SearchDeployments(request *v1.ParsedSearchRequest) ([]*v1.SearchResult, error) {
	ret := _m.Called(request)

	var r0 []*v1.SearchResult
	if rf, ok := ret.Get(0).(func(*v1.ParsedSearchRequest) []*v1.SearchResult); ok {
		r0 = rf(request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*v1.SearchResult)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*v1.ParsedSearchRequest) error); ok {
		r1 = rf(request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SearchListDeployments provides a mock function with given fields: request
func (_m *DataStore) SearchListDeployments(request *v1.ParsedSearchRequest) ([]*v1.ListDeployment, error) {
	ret := _m.Called(request)

	var r0 []*v1.ListDeployment
	if rf, ok := ret.Get(0).(func(*v1.ParsedSearchRequest) []*v1.ListDeployment); ok {
		r0 = rf(request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*v1.ListDeployment)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*v1.ParsedSearchRequest) error); ok {
		r1 = rf(request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SearchRawDeployments provides a mock function with given fields: request
func (_m *DataStore) SearchRawDeployments(request *v1.ParsedSearchRequest) ([]*v1.Deployment, error) {
	ret := _m.Called(request)

	var r0 []*v1.Deployment
	if rf, ok := ret.Get(0).(func(*v1.ParsedSearchRequest) []*v1.Deployment); ok {
		r0 = rf(request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*v1.Deployment)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*v1.ParsedSearchRequest) error); ok {
		r1 = rf(request)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateDeployment provides a mock function with given fields: deployment
func (_m *DataStore) UpdateDeployment(deployment *v1.Deployment) error {
	ret := _m.Called(deployment)

	var r0 error
	if rf, ok := ret.Get(0).(func(*v1.Deployment) error); ok {
		r0 = rf(deployment)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpsertDeployment provides a mock function with given fields: deployment
func (_m *DataStore) UpsertDeployment(deployment *v1.Deployment) error {
	ret := _m.Called(deployment)

	var r0 error
	if rf, ok := ret.Get(0).(func(*v1.Deployment) error); ok {
		r0 = rf(deployment)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
