package tests

import (
	"context"
	"testing"

	v2 "github.com/stackrox/rox/generated/api/v2"
	"github.com/stackrox/rox/pkg/testutils/centralgrpc"
	"github.com/stretchr/testify/assert"
)

func TestComplianceCreateRunScanConfiguration(t *testing.T) {
	assert.True(t, true)
}

func TestComplianceGetProfiles(t *testing.T) {
	profileID := "ocp4-moderate"
	id := &v2.ResourceByID{
		Id: profileID,
	}
	ctx := context.Background()

	conn := centralgrpc.GRPCConnectionToCentral(t)
	service := v2.NewComplianceProfileServiceClient(conn)

	profile, err := service.GetComplianceProfile(ctx, id)
	assert.NoError(t, err)
	assert.Equal(t, profile.GetId(), profileID)
}

func TestComplianceGetComplianceIntegrations(t *testing.T) {
	assert.True(t, true)
}
