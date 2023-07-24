package billingmetrics

import (
	"testing"

	"github.com/stackrox/rox/central/sensor/service/pipeline/clustermetrics"
	"github.com/stretchr/testify/assert"
)

func Test_average(t *testing.T) {
	a := average()
	assert.Equal(t, int64(0), a.TotalNodes)
	assert.Equal(t, int64(0), a.TotalCores)

	metrics := []*clustermetrics.BillingMetrics{{
		TotalNodes: 0,
		TotalCores: 100,
	}, {
		TotalNodes: 10,
		TotalCores: 0,
	}}
	a = average(metrics...)
	assert.Equal(t, int64(5), a.TotalNodes)
	assert.Equal(t, int64(50), a.TotalCores)
}
