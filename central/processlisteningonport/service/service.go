package service

import (
	"context"

	v1 "github.com/stackrox/rox/generated/api/v1"
	datastore "github.com/stackrox/rox/central/processlisteningonport/datastore"
	"github.com/stackrox/rox/pkg/grpc"
	"github.com/stackrox/rox/pkg/logging"
)

var (
	log = logging.LoggerForModule()
)

// Service provides the interface to the microservice that serves alert data.
type Service interface {
	grpc.APIService

	v1.ProcessesListeningOnPortsServiceServer
	AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error)
}

// New returns a new Service instance using the given DataStore.
func New(store datastore.DataStore) Service {
	return &serviceImpl{
		dataStore:	store,
	}
}
