// Code generated by MockGen. DO NOT EDIT.
// Source: report_gen.go
//
// Generated by this command:
//
//	mockgen -package mocks -destination mocks/report_gen.go -source report_gen.go
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	reportgenerator "github.com/stackrox/rox/central/reports/scheduler/v2/reportgenerator"
	gomock "go.uber.org/mock/gomock"
)

// MockReportGenerator is a mock of ReportGenerator interface.
type MockReportGenerator struct {
	ctrl     *gomock.Controller
	recorder *MockReportGeneratorMockRecorder
}

// MockReportGeneratorMockRecorder is the mock recorder for MockReportGenerator.
type MockReportGeneratorMockRecorder struct {
	mock *MockReportGenerator
}

// NewMockReportGenerator creates a new mock instance.
func NewMockReportGenerator(ctrl *gomock.Controller) *MockReportGenerator {
	mock := &MockReportGenerator{ctrl: ctrl}
	mock.recorder = &MockReportGeneratorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReportGenerator) EXPECT() *MockReportGeneratorMockRecorder {
	return m.recorder
}

// ProcessReportRequest mocks base method.
func (m *MockReportGenerator) ProcessReportRequest(req *reportgenerator.ReportRequest) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ProcessReportRequest", req)
}

// ProcessReportRequest indicates an expected call of ProcessReportRequest.
func (mr *MockReportGeneratorMockRecorder) ProcessReportRequest(req any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProcessReportRequest", reflect.TypeOf((*MockReportGenerator)(nil).ProcessReportRequest), req)
}
