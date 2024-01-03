package datastore

import (
	"context"
	"testing"

	ruleStorage "github.com/stackrox/rox/central/complianceoperator/v2/rules/store/postgres"
	"github.com/stackrox/rox/central/convert/internaltov2storage"
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/fixtures/fixtureconsts"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

func TestComplianceRuleDataStore(t *testing.T) {
	suite.Run(t, new(complianceRuleDataStoreTestSuite))
}

type complianceRuleDataStoreTestSuite struct {
	suite.Suite
	mockCtrl *gomock.Controller

	hasReadCtx  context.Context
	hasWriteCtx context.Context
	noAccessCtx context.Context

	dataStore DataStore
	storage   ruleStorage.Store
	db        *pgtest.TestPostgres
}

func (s *complianceRuleDataStoreTestSuite) SetupSuite() {
	s.T().Setenv(features.ComplianceEnhancements.EnvVar(), "true")
	if !features.ComplianceEnhancements.Enabled() {
		s.T().Skip("Skip tests when ComplianceEnhancements disabled")
		s.T().SkipNow()
	}
}

func (s *complianceRuleDataStoreTestSuite) SetupTest() {
	s.hasReadCtx = sac.WithGlobalAccessScopeChecker(context.Background(),
		sac.AllowFixedScopes(
			sac.AccessModeScopeKeys(storage.Access_READ_ACCESS),
			sac.ResourceScopeKeys(resources.ComplianceOperator)))
	s.hasWriteCtx = sac.WithGlobalAccessScopeChecker(context.Background(),
		sac.AllowFixedScopes(
			sac.AccessModeScopeKeys(storage.Access_READ_ACCESS, storage.Access_READ_WRITE_ACCESS),
			sac.ResourceScopeKeys(resources.ComplianceOperator)))
	s.noAccessCtx = sac.WithGlobalAccessScopeChecker(context.Background(), sac.DenyAllAccessScopeChecker())

	s.mockCtrl = gomock.NewController(s.T())

	s.db = pgtest.ForT(s.T())

	s.storage = ruleStorage.New(s.db)
	s.dataStore = New(s.storage)
}

func (s *complianceRuleDataStoreTestSuite) TearDownTest() {
	s.db.Teardown(s.T())
}

func (s *complianceRuleDataStoreTestSuite) TestUpsertResult() {
	// make sure we have nothing
	ruleIDs, err := s.storage.GetIDs(s.hasReadCtx)
	s.Require().NoError(err)
	s.Require().Empty(ruleIDs)

	rec1 := getTestRec()
	rec2 := getTestRec()
	ids := []string{rec1.GetRuleUid(), rec2.GetRuleUid()}

	s.Require().NoError(s.dataStore.UpsertRule(s.hasWriteCtx, internaltov2storage.ComplianceOperatorRule(rec1, fixtureconsts.Cluster1)))
	s.Require().NoError(s.dataStore.UpsertRule(s.hasWriteCtx, internaltov2storage.ComplianceOperatorRule(rec2, fixtureconsts.Cluster2)))

	count, err := s.storage.Count(s.hasReadCtx)
	s.Require().NoError(err)
	s.Require().Equal(len(ids), count)

	// upsert with read context
	s.Require().Error(s.dataStore.UpsertRule(s.hasReadCtx, internaltov2storage.ComplianceOperatorRule(rec2, fixtureconsts.Cluster2)))

	_, found, err := s.storage.Get(s.hasReadCtx, rec1.GetRuleUid())
	s.Require().NoError(err)
	s.Require().True(found)
	//s.Require().Equal(rec1, retrieveRec1)
}

func getTestRec() *central.ComplianceOperatorRuleV2 {
	annotations := make(map[string]string, 5)
	annotations["policies.open-cluster-management.io/standards"] = "NERC-CIP,NIST-800-53,PCI-DSS,CIS-OCP"
	annotations["control.compliance.openshift.io/NERC-CIP"] = "CIP-003-8 R6;CIP-004-6 R3;CIP-007-3 R6.1"
	annotations["control.compliance.openshift.io/NIST-800-53"] = "CM-6;CM-6(1)"
	annotations["control.compliance.openshift.io/PCI-DSS"] = "Req-2.2"
	annotations["control.compliance.openshift.io/CIS-OCP"] = "5.1.6"

	return &central.ComplianceOperatorRuleV2{
		RuleId:      "",
		RuleUid:     uuid.NewV4().String(),
		Name:        "test-name",
		RuleType:    "node",
		Severity:    0,
		Labels:      nil,
		Annotations: annotations,
		Title:       "",
		Description: "",
		Rationale:   "",
		Fixes:       nil,
		Warning:     "",
	}
}
