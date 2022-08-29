// Code generated by MockGen. DO NOT EDIT.
// Source: client.go

// Package mock_castai is a generated GoMock package.
package mock_castai

import (
	context "context"
	reflect "reflect"

	castai "github.com/castai/sec-agent/castai"
	gomock "github.com/golang/mock/gomock"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// SendLogs mocks base method.
func (m *MockClient) SendLogs(ctx context.Context, req *castai.LogEvent) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendLogs", ctx, req)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendLogs indicates an expected call of SendLogs.
func (mr *MockClientMockRecorder) SendLogs(ctx, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendLogs", reflect.TypeOf((*MockClient)(nil).SendLogs), ctx, req)
}