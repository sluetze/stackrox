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

type TestSingleKeyStructsStoreSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	store       Store
	testDB      *pgtest.TestPostgres
}

func TestTestSingleKeyStructsStore(t *testing.T) {
	suite.Run(t, new(TestSingleKeyStructsStoreSuite))
}

func (s *TestSingleKeyStructsStoreSuite) SetupSuite() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(env.PostgresDatastoreEnabled.EnvVar(), "true")

	if !env.PostgresDatastoreEnabled.BooleanSetting() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.Postgres)
}

func (s *TestSingleKeyStructsStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE test_single_key_structs CASCADE")
	s.T().Log("test_single_key_structs", tag)
	s.NoError(err)
}

func (s *TestSingleKeyStructsStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
	s.envIsolator.RestoreAll()
}

func (s *TestSingleKeyStructsStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	testSingleKeyStruct := &storage.TestSingleKeyStruct{}
	s.NoError(testutils.FullInit(testSingleKeyStruct, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundTestSingleKeyStruct, exists, err := store.Get(ctx, testSingleKeyStruct.GetKey())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundTestSingleKeyStruct)

	withNoAccessCtx := sac.WithNoAccess(ctx)

	s.NoError(store.Upsert(ctx, testSingleKeyStruct))
	foundTestSingleKeyStruct, exists, err = store.Get(ctx, testSingleKeyStruct.GetKey())
	s.NoError(err)
	s.True(exists)
	s.Equal(testSingleKeyStruct, foundTestSingleKeyStruct)

	testSingleKeyStructCount, err := store.Count(ctx)
	s.NoError(err)
	s.Equal(1, testSingleKeyStructCount)
	testSingleKeyStructCount, err = store.Count(withNoAccessCtx)
	s.NoError(err)
	s.Zero(testSingleKeyStructCount)

	testSingleKeyStructExists, err := store.Exists(ctx, testSingleKeyStruct.GetKey())
	s.NoError(err)
	s.True(testSingleKeyStructExists)
	s.NoError(store.Upsert(ctx, testSingleKeyStruct))
	s.ErrorIs(store.Upsert(withNoAccessCtx, testSingleKeyStruct), sac.ErrResourceAccessDenied)

	foundTestSingleKeyStruct, exists, err = store.Get(ctx, testSingleKeyStruct.GetKey())
	s.NoError(err)
	s.True(exists)
	s.Equal(testSingleKeyStruct, foundTestSingleKeyStruct)

	s.NoError(store.Delete(ctx, testSingleKeyStruct.GetKey()))
	foundTestSingleKeyStruct, exists, err = store.Get(ctx, testSingleKeyStruct.GetKey())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundTestSingleKeyStruct)
	s.NoError(store.Delete(withNoAccessCtx, testSingleKeyStruct.GetKey()))

	var testSingleKeyStructs []*storage.TestSingleKeyStruct
	for i := 0; i < 200; i++ {
		testSingleKeyStruct := &storage.TestSingleKeyStruct{}
		s.NoError(testutils.FullInit(testSingleKeyStruct, testutils.UniqueInitializer(), testutils.JSONFieldsFilter))
		testSingleKeyStructs = append(testSingleKeyStructs, testSingleKeyStruct)
	}

	s.NoError(store.UpsertMany(ctx, testSingleKeyStructs))
	allTestSingleKeyStruct, err := store.GetAll(ctx)
	s.NoError(err)
	s.ElementsMatch(testSingleKeyStructs, allTestSingleKeyStruct)

	testSingleKeyStructCount, err = store.Count(ctx)
	s.NoError(err)
	s.Equal(200, testSingleKeyStructCount)
}
