package service

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/driftprogramming/pgxpoolmock"
	"github.com/pkg/errors"
	clusterMocks "github.com/stackrox/rox/central/cluster/datastore/mocks"
	configMocks "github.com/stackrox/rox/central/config/datastore/mocks"
	"github.com/stackrox/rox/central/globaldb"
	groupMocks "github.com/stackrox/rox/central/group/datastore/mocks"
	notifierMocks "github.com/stackrox/rox/central/notifier/datastore/mocks"
	roleMocks "github.com/stackrox/rox/central/role/datastore/mocks"
	"github.com/stackrox/rox/central/sensor/service/connection"
	connectionMocks "github.com/stackrox/rox/central/sensor/service/connection/mocks"
	"github.com/stackrox/rox/central/sensor/telemetry"
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	permissionsMocks "github.com/stackrox/rox/pkg/auth/permissions/mocks"
	"github.com/stackrox/rox/pkg/httputil/mock"
	"github.com/stackrox/rox/pkg/postgres/mocks"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stackrox/rox/pkg/version/testutils"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

func TestDebugService(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(debugServiceTestSuite))
}

type debugServiceTestSuite struct {
	suite.Suite

	mockCtrl *gomock.Controller
	noneCtx  context.Context

	groupsMock        *groupMocks.MockDataStore
	rolesMock         *roleMocks.MockDataStore
	notifiersMock     *notifierMocks.MockDataStore
	configMock        *configMocks.MockDataStore
	clustersMock      *clusterMocks.MockDataStore
	sensorConnMgrMock *connectionMocks.MockManager

	service *serviceImpl
}

func (s *debugServiceTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.noneCtx = sac.WithGlobalAccessScopeChecker(context.Background(), sac.DenyAllAccessScopeChecker())

	s.groupsMock = groupMocks.NewMockDataStore(s.mockCtrl)
	s.rolesMock = roleMocks.NewMockDataStore(s.mockCtrl)
	s.notifiersMock = notifierMocks.NewMockDataStore(s.mockCtrl)
	s.configMock = configMocks.NewMockDataStore(s.mockCtrl)
	s.clustersMock = clusterMocks.NewMockDataStore(s.mockCtrl)
	s.sensorConnMgrMock = connectionMocks.NewMockManager(s.mockCtrl)

	s.service = &serviceImpl{
		clusters:             s.clustersMock,
		sensorConnMgr:        s.sensorConnMgrMock,
		telemetryGatherer:    nil,
		store:                nil,
		authzTraceSink:       nil,
		authProviderRegistry: nil,
		groupDataStore:       s.groupsMock,
		roleDataStore:        s.rolesMock,
		configDataStore:      s.configMock,
		notifierDataStore:    s.notifiersMock,
	}
}

func (s *debugServiceTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

func (s *debugServiceTestSuite) TestGetGroups() {
	s.groupsMock.EXPECT().GetAll(gomock.Any()).Return(nil, errors.New("Test"))
	_, err := s.service.getGroups(s.noneCtx)
	s.Error(err, "expected error propagation")

	expectedGroups := []*storage.Group{
		{
			RoleName: "test",
			Props: &storage.GroupProperties{
				AuthProviderId: "1",
				Key:            "test",
				Value:          "1",
			},
		},
	}
	s.groupsMock.EXPECT().GetAll(gomock.Any()).Return(expectedGroups, nil)
	actualGroups, err := s.service.getGroups(s.noneCtx)

	s.NoError(err)
	s.Equal(expectedGroups, actualGroups)
}

func (s *debugServiceTestSuite) TestGetRoles() {
	s.rolesMock.EXPECT().GetAllRoles(gomock.Any()).Return(nil, errors.New("Test"))
	_, err := s.service.getRoles(s.noneCtx)
	s.Error(err, "expected error propagation")

	allRoles := []*storage.Role{
		{
			Name: "Test",
		},
	}
	s.rolesMock.EXPECT().GetAllRoles(gomock.Any()).Return(allRoles, nil)

	resolvedRole := permissionsMocks.NewMockResolvedRole(s.mockCtrl)
	s.rolesMock.EXPECT().GetAndResolveRole(gomock.Any(), allRoles[0].Name).Return(resolvedRole, nil)
	resolvedRole.EXPECT().GetPermissions().Return(map[string]storage.Access{
		"TestNone":      0,
		"TestRead":      1,
		"TestReadWrite": 2,
	})
	expectedAccessScope := storage.SimpleAccessScope{
		Name: "TestScope",
	}
	resolvedRole.EXPECT().GetAccessScope().Return(&expectedAccessScope)
	actualRoles, err := s.service.getRoles(s.noneCtx)

	expectedRoles := []*diagResolvedRole{
		{
			Role: allRoles[0],
			PermissionSet: map[string]string{
				"TestNone":      storage.Access_NO_ACCESS.String(),
				"TestRead":      storage.Access_READ_ACCESS.String(),
				"TestReadWrite": storage.Access_READ_WRITE_ACCESS.String(),
			},
			AccessScope: &expectedAccessScope,
		},
	}

	s.NoError(err)
	s.EqualValues(expectedRoles, actualRoles)
}

func (s *debugServiceTestSuite) TestGetNotifiers() {
	s.notifiersMock.EXPECT().GetScrubbedNotifiers(gomock.Any()).Return(nil, errors.New("Test"))
	_, err := s.service.getNotifiers(s.noneCtx)
	s.Error(err, "expected error propagation")

	expectedNotifiers := []*storage.Notifier{
		{
			Name: "test",
			Config: &storage.Notifier_Pagerduty{
				Pagerduty: &storage.PagerDuty{
					ApiKey: "******",
				},
			},
		},
	}
	s.notifiersMock.EXPECT().GetScrubbedNotifiers(gomock.Any()).Return(expectedNotifiers, nil)
	actualNotifiers, err := s.service.getNotifiers(s.noneCtx)

	s.NoError(err)
	s.EqualValues(expectedNotifiers, actualNotifiers)
}

func (s *debugServiceTestSuite) TestGetConfig() {
	s.configMock.EXPECT().GetConfig(gomock.Any()).Return(nil, errors.New("Test"))
	_, err := s.service.getConfig(s.noneCtx)
	s.Error(err, "expected error propagation")

	expectedConfig := &storage.Config{
		PublicConfig: &storage.PublicConfig{
			LoginNotice: &storage.LoginNotice{
				Text: "test",
			},
		},
		PrivateConfig: &storage.PrivateConfig{
			ImageRetentionDurationDays: 1,
		},
	}
	s.configMock.EXPECT().GetConfig(gomock.Any()).Return(expectedConfig, nil)
	actualConfig, err := s.service.getConfig(s.noneCtx)

	s.NoError(err)
	s.Equal(expectedConfig, actualConfig)
}

func (s *debugServiceTestSuite) TestGetBundle() {
	stubTime := time.Date(2023, 03, 14, 0, 0, 0, 0, time.UTC)
	now = func() time.Time {
		return stubTime
	}

	w := mock.NewResponseWriter()
	testutils.SetVersion(s.T(), testutils.GetExampleVersion(s.T()))
	db := mocks.NewMockDB(s.mockCtrl)
	pgxRows := pgxpoolmock.NewRows([]string{"server_version"}).AddRow("15.1").ToPgxRows()
	// Workaround for https://github.com/driftprogramming/pgxpoolmock/issues/8
	pgxRows.Next()
	db.EXPECT().QueryRow(gomock.Any(), "SHOW server_version;").Return(pgxRows)
	globaldb.SetPostgresTest(s.T(), db)

	s.configMock.EXPECT().GetConfig(gomock.Any()).Return(&storage.Config{}, nil)
	numberOfClusters := 100
	numberOfSensorsPerCluster := 10
	clusters := make([]*storage.Cluster, 0, numberOfClusters)
	connections := make([]connection.SensorConnection, 0, numberOfSensorsPerCluster*numberOfClusters)
	for i := 0; i < numberOfClusters; i++ {
		clusterId := fmt.Sprintf("%d", i)
		clusters = append(clusters, &storage.Cluster{Id: clusterId})
		for j := 0; j < numberOfSensorsPerCluster; j++ {
			connMock := connectionMocks.NewMockSensorConnection(s.mockCtrl)
			connMock.EXPECT().HasCapability(gomock.Any()).Return(true).Times(2)
			connMock.EXPECT().ClusterID().Return(clusterId).Times(2)
			connMock.EXPECT().Telemetry().Return(&dummyTelemetry{}).Times(2)
			connections = append(connections, connMock)
		}
	}
	s.clustersMock.EXPECT().GetClusters(gomock.Any()).Return(clusters, nil).Times(2)
	s.sensorConnMgrMock.EXPECT().GetActiveConnections().Return(connections).Times(2)
	s.service.writeZippedDebugDump(context.Background(), w, "debug.zip", debugDumpOptions{
		logs:              fullK8sIntrospectionData,
		telemetryMode:     noTelemetry,
		withCPUProfile:    false,
		withLogImbue:      false,
		withAccessControl: false,
		withNotifiers:     false,
		withCentral:       true,
		clusters:          nil,
		since:             time.Now(),
	})

	s.Equal(http.StatusOK, w.Code)

	body, err := io.ReadAll(w.Data)
	s.Require().NoError(err)

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	s.Require().NoError(err)

	s.Assert().Len(zipReader.File, numberOfClusters*numberOfSensorsPerCluster+8)
	for _, zipFile := range zipReader.File {
		s.T().Log("Reading file:", zipFile.Name)
		s.Assert().Equal(stubTime, zipFile.Modified.UTC())
	}
}

type dummyTelemetry struct {
}

func (s *dummyTelemetry) PullKubernetesInfo(ctx context.Context, cb telemetry.KubernetesInfoChunkCallback, since time.Time) error {
	data := &central.TelemetryResponsePayload_KubernetesInfo{
		Files: []*central.TelemetryResponsePayload_KubernetesInfo_File{
			{Path: "path", Contents: []byte("content")},
		},
	}
	return cb(ctx, data)
}
func (s *dummyTelemetry) PullClusterInfo(ctx context.Context, cb telemetry.ClusterInfoCallback) error {
	return nil
}
func (s *dummyTelemetry) PullMetrics(ctx context.Context, cb telemetry.MetricsInfoChunkCallback) error {
	return nil
}
func (s *dummyTelemetry) ProcessTelemetryDataResponse(resp *central.PullTelemetryDataResponse) error {
	return nil
}
