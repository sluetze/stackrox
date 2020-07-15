package docker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/golang/mock/gomock"
	"github.com/stackrox/rox/central/compliance/framework"
	"github.com/stackrox/rox/central/compliance/framework/mocks"
	"github.com/stackrox/rox/generated/internalapi/compliance"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/docker/types"
	"github.com/stackrox/rox/pkg/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerImagesChecks(t *testing.T) {
	cases := []struct {
		name   string
		image  types.ImageWrap
		status framework.Status
	}{
		{
			name: "CIS_Docker_v1_2_0:4_6",
			image: types.ImageWrap{
				Image: types.ImageInspect{
					Config: &types.Config{},
				},
			},
			status: framework.FailStatus,
		},
		{
			name: "CIS_Docker_v1_2_0:4_6",
			image: types.ImageWrap{
				Image: types.ImageInspect{
					Config: &types.Config{
						Healthcheck: &container.HealthConfig{},
					},
				},
			},
			status: framework.PassStatus,
		},
		{
			name: "CIS_Docker_v1_2_0:4_9",
			image: types.ImageWrap{
				History: []image.HistoryResponseItem{
					{
						CreatedBy: "/bin/sh -c #(nop) WORKDIR /usr/share/grafana",
					},
					{
						CreatedBy: "add file: hello",
					},
				},
			},
			status: framework.FailStatus,
		},
		{
			name: "CIS_Docker_v1_2_0:4_9",
			image: types.ImageWrap{
				History: []image.HistoryResponseItem{
					{
						CreatedBy: "/bin/sh -c #(nop) WORKDIR /usr/share/grafana",
					},
				},
			},
			status: framework.PassStatus,
		},
		{
			name: "CIS_Docker_v1_2_0:4_7",
			image: types.ImageWrap{
				History: []image.HistoryResponseItem{
					{
						CreatedBy: "/bin/sh -c #(nop) WORKDIR /usr/share/grafana",
					},
				},
			},
			status: framework.PassStatus,
		},
		{
			name: "CIS_Docker_v1_2_0:4_7",
			image: types.ImageWrap{
				History: []image.HistoryResponseItem{
					{
						CreatedBy: "/bin/sh -c #(nop) apk update",
					},
				},
			},
			status: framework.FailStatus,
		},
	}

	for _, cIt := range cases {
		c := cIt
		t.Run(strings.Replace(c.name, ":", "-", -1), func(t *testing.T) {
			t.Parallel()

			registry := framework.RegistrySingleton()
			check := registry.Lookup(c.name)
			require.NotNil(t, check)

			testCluster := &storage.Cluster{
				Id: uuid.NewV4().String(),
			}
			testNodes := createTestNodes("A", "B")

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			domain := framework.NewComplianceDomain(testCluster, testNodes, nil, nil)
			data := mocks.NewMockComplianceDataRepository(mockCtrl)

			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			err := json.NewEncoder(gz).Encode(&types.Data{
				Images: []types.ImageWrap{
					c.image,
				},
			})
			require.NoError(t, err)
			require.NoError(t, gz.Close())

			data.EXPECT().HostScraped(nodeNameMatcher("A")).AnyTimes().Return(&compliance.ComplianceReturn{
				DockerData: &compliance.GZIPDataChunk{Gzip: buf.Bytes()},
			})
			data.EXPECT().HostScraped(nodeNameMatcher("B")).AnyTimes().Return(&compliance.ComplianceReturn{
				DockerData: &compliance.GZIPDataChunk{Gzip: buf.Bytes()},
			})

			run, err := framework.NewComplianceRun(check)
			require.NoError(t, err)
			err = run.Run(context.Background(), domain, data)
			require.NoError(t, err)

			results := run.GetAllResults()
			checkResults := results[c.name]
			require.NotNil(t, checkResults)

			require.Len(t, checkResults.Evidence(), 0)
			for _, node := range domain.Nodes() {
				nodeResults := checkResults.ForChild(node)
				require.NoError(t, nodeResults.Error())
				require.Len(t, nodeResults.Evidence(), 1)
				assert.Equal(t, c.status, nodeResults.Evidence()[0].Status)
			}
		})
	}
}
