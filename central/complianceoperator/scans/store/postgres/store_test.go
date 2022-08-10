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

type ComplianceOperatorScansStoreSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
	store       Store
	testDB      *pgtest.TestPostgres
}

func TestComplianceOperatorScansStore(t *testing.T) {
	suite.Run(t, new(ComplianceOperatorScansStoreSuite))
}

func (s *ComplianceOperatorScansStoreSuite) SetupSuite() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(features.PostgresDatastore.EnvVar(), "true")

	if !features.PostgresDatastore.Enabled() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}

	s.testDB = pgtest.ForT(s.T())
	s.store = New(s.testDB.Pool)
}

func (s *ComplianceOperatorScansStoreSuite) SetupTest() {
	ctx := sac.WithAllAccess(context.Background())
	tag, err := s.testDB.Exec(ctx, "TRUNCATE compliance_operator_scans CASCADE")
	s.T().Log("compliance_operator_scans", tag)
	s.NoError(err)
}

func (s *ComplianceOperatorScansStoreSuite) TearDownSuite() {
	s.testDB.Teardown(s.T())
	s.envIsolator.RestoreAll()
}

func (s *ComplianceOperatorScansStoreSuite) TestStore() {
	ctx := sac.WithAllAccess(context.Background())

	store := s.store

	complianceOperatorScan := &storage.ComplianceOperatorScan{}
	s.NoError(testutils.FullInit(complianceOperatorScan, testutils.SimpleInitializer(), testutils.JSONFieldsFilter))

	foundComplianceOperatorScan, exists, err := store.Get(ctx, complianceOperatorScan.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundComplianceOperatorScan)

}
