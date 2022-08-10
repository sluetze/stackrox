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

type DeploymentsStoreSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	store       Store
	testDB      *pgtest.TestPostgres
}

func TestDeploymentsStore(t *testing.T) {
	suite.Run(t, new(DeploymentsStoreSuite))
}

func (s *DeploymentsStoreSuite) SetupSuite() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(features.PostgresDatastore.EnvVar(), "true")

	if !features.PostgresDatastore.Enabled() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.Pool)
}

func (s *DeploymentsStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE deployments CASCADE")
	s.T().Log("deployments", tag)
	s.NoError(err)
}

func (s *DeploymentsStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
	s.envIsolator.RestoreAll()
}

func (s *DeploymentsStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	deployment := &storage.Deployment{}
	s.NoError(testutils.FullInit(deployment, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundDeployment, exists, err := store.Get(ctx, deployment.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundDeployment)

}
