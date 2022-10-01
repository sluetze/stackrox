// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package postgres

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stretchr/testify/suite"
)

type TestParent1StoreSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	store       Store
	testDB      *pgtest.TestPostgres
}

func TestTestParent1Store(t *testing.T) {
	suite.Run(t, new(TestParent1StoreSuite))
}

func (s *TestParent1StoreSuite) SetupSuite() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(env.PostgresDatastoreEnabled.EnvVar(), "true")

	if !env.PostgresDatastoreEnabled.BooleanSetting() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.Postgres)
}

func (s *TestParent1StoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE test_parent1 CASCADE")
	s.T().Log("test_parent1", tag)
	s.NoError(err)
}

func (s *TestParent1StoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
	s.envIsolator.RestoreAll()
}

func (s *TestParent1StoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	testParent1 := &storage.TestParent1{}
	s.NoError(testutils.FullInit(testParent1, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundTestParent1, exists, err := store.Get(ctx, testParent1.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundTestParent1)

}
