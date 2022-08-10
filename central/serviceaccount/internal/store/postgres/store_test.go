// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package postgres

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stretchr/testify/suite"
)

type ServiceAccountsStoreSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	store       Store
	testDB      *pgtest.TestPostgres
}

func TestServiceAccountsStore(t *testing.T) {
	suite.Run(t, new(ServiceAccountsStoreSuite))
}

func (s *ServiceAccountsStoreSuite) SetupSuite() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(features.PostgresDatastore.EnvVar(), "true")

	if !features.PostgresDatastore.Enabled() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.Pool)
}

func (s *ServiceAccountsStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE service_accounts CASCADE")
	s.T().Log("service_accounts", tag)
	s.NoError(err)
}

func (s *ServiceAccountsStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
	s.envIsolator.RestoreAll()
}

func (s *ServiceAccountsStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	serviceAccount := &storage.ServiceAccount{}
	s.NoError(testutils.FullInit(serviceAccount, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundServiceAccount, exists, err := store.Get(ctx, serviceAccount.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundServiceAccount)

}
