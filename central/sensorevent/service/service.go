package service

import (
	"github.com/stackrox/rox/central/sensorevent/service/streamer"
	"github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/grpc"
	"golang.org/x/net/context"
)

// Service is the GRPC service interface that provides the entry point for processing deployment events.
type Service interface {
	grpc.APIService

	AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error)

	RecordEvent(stream v1.SensorEventService_RecordEventServer) error
}

// New returns a new instance of service.
func New(streamManager streamer.Manager) Service {
	return &serviceImpl{
		streamManager: streamManager,
	}
}
