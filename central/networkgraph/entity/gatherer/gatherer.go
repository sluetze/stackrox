package gatherer

import (
	entityDataStore "github.com/stackrox/rox/central/networkgraph/entity/datastore"
	"github.com/stackrox/rox/central/sensor/service/connection"
)

// NetworkGraphDefaultExtSrcsGatherer provides functionality to update the storage.NetworkEntity storage with default network graph
// external sources.
type NetworkGraphDefaultExtSrcsGatherer interface {
	Start()
	Stop()

	Update() error
}

// NewNetworkGraphDefaultExtSrcsGatherer returns an instance of NetworkGraphDefaultExtSrcsGatherer as per the offline mode setting.
func NewNetworkGraphDefaultExtSrcsGatherer(networkEntityDS entityDataStore.EntityDataStore,
	sensorConnMgr connection.Manager) NetworkGraphDefaultExtSrcsGatherer {
	return newDefaultExtNetworksGatherer(networkEntityDS, sensorConnMgr)
}
