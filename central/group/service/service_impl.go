package service

import (
	"context"

	"github.com/gogo/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/stackrox/rox/central/group/datastore"
	"github.com/stackrox/rox/central/group/datastore/serialize"
	"github.com/stackrox/rox/central/role/resources"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/auth/permissions"
	"github.com/stackrox/rox/pkg/grpc/authz"
	"github.com/stackrox/rox/pkg/grpc/authz/perrpc"
	"github.com/stackrox/rox/pkg/grpc/authz/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	authorizer = perrpc.FromMap(map[authz.Authorizer][]string{
		user.With(permissions.View(resources.Group)): {
			"/v1.GroupService/GetGroups",
			"/v1.GroupService/GetGroup",
		},
		user.With(permissions.Modify(resources.Group)): {
			"/v1.GroupService/BatchUpdate",
			"/v1.GroupService/CreateGroup",
			"/v1.GroupService/UpdateGroup",
			"/v1.GroupService/DeleteGroup",
		},
	})
)

type serviceImpl struct {
	groups datastore.DataStore
}

func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterGroupServiceServer(grpcServer, s)
}

func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterGroupServiceHandler(ctx, mux, conn)
}

func (*serviceImpl) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, authorizer.Authorized(ctx, fullMethodName)
}

func (s *serviceImpl) GetGroups(ctx context.Context, _ *v1.Empty) (*v1.GetGroupsResponse, error) {
	groups, err := s.groups.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	return &v1.GetGroupsResponse{Groups: groups}, nil
}

func (s *serviceImpl) GetGroup(ctx context.Context, props *storage.GroupProperties) (*storage.Group, error) {
	group, err := s.groups.Get(ctx, props)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, status.Errorf(codes.NotFound, "group %q not found", proto.MarshalTextString(props))
	}
	return group, nil
}

func (s *serviceImpl) BatchUpdate(ctx context.Context, req *v1.GroupBatchUpdateRequest) (*v1.Empty, error) {
	for _, group := range req.GetRequiredGroups() {
		if err := validate(group); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	removed, updated, added := diffGroups(req.GetPreviousGroups(), req.GetRequiredGroups())
	if err := s.groups.Mutate(ctx, removed, updated, added); err != nil {
		return nil, err
	}
	return &v1.Empty{}, nil
}

func (s *serviceImpl) CreateGroup(ctx context.Context, group *storage.Group) (*v1.Empty, error) {
	if err := validate(group); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	err := s.groups.Add(ctx, group)
	if err != nil {
		return nil, err
	}
	return &v1.Empty{}, nil
}

func (s *serviceImpl) UpdateGroup(ctx context.Context, group *storage.Group) (*v1.Empty, error) {
	if err := validate(group); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	err := s.groups.Update(ctx, group)
	if err != nil {
		return nil, err
	}
	return &v1.Empty{}, nil
}

func (s *serviceImpl) DeleteGroup(ctx context.Context, props *storage.GroupProperties) (*v1.Empty, error) {
	err := s.groups.Remove(ctx, props)
	if err != nil {
		return nil, err
	}
	return &v1.Empty{}, nil
}

// Helper function that does a diff between two sets of groups and comes up with needed mutations.
func diffGroups(previous []*storage.Group, required []*storage.Group) (removed []*storage.Group, updated []*storage.Group, added []*storage.Group) {
	previousByProps := make(map[string]*storage.Group)
	for _, group := range previous {
		previousByProps[serialize.PropsKey(group.GetProps())] = group
	}
	requiredByProps := make(map[string]*storage.Group)
	for _, group := range required {
		requiredByProps[serialize.PropsKey(group.GetProps())] = group
	}

	for key, group := range previousByProps {
		if _, hasRequiredGroup := requiredByProps[key]; !hasRequiredGroup {
			removed = append(removed, group)
		}
	}
	for key, group := range requiredByProps {
		if previousGroup, hasPreviousGroup := previousByProps[key]; hasPreviousGroup {
			if !proto.Equal(previousGroup, group) {
				updated = append(updated, group)
			}
		} else {
			added = append(added, group)
		}
	}
	return
}
