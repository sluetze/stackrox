// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package n14ton15

import (
	"context"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	legacy "github.com/stackrox/rox/migrator/migrations/n_14_to_n_15_postgres_compliance_operator_profiles/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_14_to_n_15_postgres_compliance_operator_profiles/postgres"
	pghelper "github.com/stackrox/rox/migrator/migrations/postgreshelper"

	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/rocksdb"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stackrox/rox/pkg/testutils/rocksdbtest"
	"github.com/stretchr/testify/suite"
)

func TestMigration(t *testing.T) {
	suite.Run(t, new(postgresMigrationSuite))
}

type postgresMigrationSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	ctx         context.Context

	legacyDB   *rocksdb.RocksDB
	postgresDB *pghelper.TestPostgres
}

var _ suite.TearDownTestSuite = (*postgresMigrationSuite)(nil)

func (s *postgresMigrationSuite) SetupTest() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(env.PostgresDatastoreEnabled.EnvVar(), "true")
	if !env.PostgresDatastoreEnabled.BooleanSetting() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	var err error
	s.legacyDB, err = rocksdb.NewTemp(s.T().Name())
	s.NoError(err)

	s.Require().NoError(err)

	s.ctx = sac.WithAllAccess(context.Background())
	s.postgresDB = pghelper.ForT(s.T(), true)
}

func (s *postgresMigrationSuite) TearDownTest() {
	rocksdbtest.TearDownRocksDB(s.legacyDB)
	s.postgresDB.Teardown(s.T())
}

func (s *postgresMigrationSuite) TestComplianceOperatorProfileMigration() {
	newStore := pgStore.New(s.postgresDB.Postgres)
	legacyStore, err := legacy.New(s.legacyDB)
	s.NoError(err)

	// Prepare data and write to legacy DB
	var complianceOperatorProfiles []*storage.ComplianceOperatorProfile
	for i := 0; i < 200; i++ {
		complianceOperatorProfile := &storage.ComplianceOperatorProfile{}
		s.NoError(testutils.FullInit(complianceOperatorProfile, testutils.UniqueInitializer(), testutils.JSONFieldsFilter))
		complianceOperatorProfiles = append(complianceOperatorProfiles, complianceOperatorProfile)
	}

	s.NoError(legacyStore.UpsertMany(s.ctx, complianceOperatorProfiles))

	// Move
	s.NoError(move(s.postgresDB.GetGormDB(), s.postgresDB.Postgres, legacyStore))

	// Verify
	count, err := newStore.Count(s.ctx)
	s.NoError(err)
	s.Equal(len(complianceOperatorProfiles), count)
	for _, complianceOperatorProfile := range complianceOperatorProfiles {
		fetched, exists, err := newStore.Get(s.ctx, complianceOperatorProfile.GetId())
		s.NoError(err)
		s.True(exists)
		s.Equal(complianceOperatorProfile, fetched)
	}
}
