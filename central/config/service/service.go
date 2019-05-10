package service

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/stackrox/rox/central/config/datastore"
	"github.com/stackrox/rox/central/role/resources"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/auth/permissions"
	pkgGRPC "github.com/stackrox/rox/pkg/grpc"
	"github.com/stackrox/rox/pkg/grpc/authz"
	"github.com/stackrox/rox/pkg/grpc/authz/perrpc"
	"github.com/stackrox/rox/pkg/grpc/authz/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	authorizer = perrpc.FromMap(map[authz.Authorizer][]string{
		user.With(): {
			"/v1.ConfigService/GetLoginConfig",
		},
		user.With(permissions.View(resources.Config)): {
			"/v1.ConfigService/GetConfig",
		},
		user.With(permissions.Modify(resources.Config)): {
			"/v1.ConfigService/PutConfig",
		},
	})
)

// Service provides the interface to modify Central config
type Service interface {
	pkgGRPC.APIService

	AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error)

	v1.ConfigServiceServer
}

// New returns a new Service instance using the given DataStore.
func New(datastore datastore.DataStore) Service {
	return &serviceImpl{
		datastore: datastore,
	}
}

type serviceImpl struct {
	datastore datastore.DataStore
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterConfigServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterConfigServiceHandler(ctx, mux, conn)
}

// AuthFuncOverride specifies the auth criteria for this API.
func (s *serviceImpl) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, authorizer.Authorized(ctx, fullMethodName)
}

// GetLoginConfig returns the specific config for the login page
func (s *serviceImpl) GetLoginConfig(ctx context.Context, _ *v1.Empty) (*storage.LoginNotice, error) {
	config, err := s.datastore.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	if config.GetLoginNotice() == nil {
		return &storage.LoginNotice{}, nil
	}
	return config.GetLoginNotice(), nil
}

// GetConfig returns Central's config
func (s *serviceImpl) GetConfig(ctx context.Context, _ *v1.Empty) (*storage.Config, error) {
	config, err := s.datastore.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// PutConfig updates Central's config
func (s *serviceImpl) PutConfig(ctx context.Context, req *v1.PutConfigRequest) (*storage.Config, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config must be specified")
	}
	if err := s.datastore.UpdateConfig(ctx, req.GetConfig()); err != nil {
		return nil, err
	}
	return req.GetConfig(), nil
}
