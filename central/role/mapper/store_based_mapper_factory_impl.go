package mapper

import (
	groupDataStore "github.com/stackrox/rox/central/group/datastore"
	roleDataStore "github.com/stackrox/rox/central/role/datastore"
	teamsDataStore "github.com/stackrox/rox/central/teams/datastore"
	userDataStore "github.com/stackrox/rox/central/user/datastore"
	"github.com/stackrox/rox/pkg/auth/permissions"
)

// NewStoreBasedMapperFactory returns a new instance of a Factory which will use the given stores to create RoleMappers.
func NewStoreBasedMapperFactory(groups groupDataStore.DataStore, roles roleDataStore.DataStore, users userDataStore.DataStore, teams teamsDataStore.DataStore) permissions.RoleMapperFactory {
	return &storeBasedMapperFactoryImpl{
		groups: groups,
		roles:  roles,
		users:  users,
		teams:  teams,
	}
}

type storeBasedMapperFactoryImpl struct {
	groups groupDataStore.DataStore
	roles  roleDataStore.DataStore
	users  userDataStore.DataStore
	teams  teamsDataStore.DataStore
}

// GetRoleMapper returns a role mapper for the given auth provider.
func (rm *storeBasedMapperFactoryImpl) GetRoleMapper(authProviderID string) permissions.RoleMapper {
	return &storeBasedMapperImpl{
		authProviderID: authProviderID,
		groups:         rm.groups,
		roles:          rm.roles,
		users:          rm.users,
		teams:          rm.teams,
	}
}
