package scanners

import (
	"sort"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scanners/types"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/sync"
)

type setImpl struct {
	lock sync.RWMutex

	factory      Factory
	integrations map[string]types.ImageScanner
}

var registryDependentScanners = set.NewStringSet("clair", "clairify")

// GetAll returns the set of integrations that are active.
func (e *setImpl) GetAll() []types.ImageScanner {
	e.lock.RLock()
	defer e.lock.RUnlock()

	integrations := make([]types.ImageScanner, 0, len(e.integrations))
	for _, i := range e.integrations {
		integrations = append(integrations, i)
	}
	sort.Slice(integrations, func(i, j int) bool {
		return !registryDependentScanners.Contains(integrations[i].Type())
	})
	return integrations
}

// Clear removes all present integrations.
func (e *setImpl) Clear() {
	e.lock.Lock()
	defer e.lock.Unlock()

	e.integrations = make(map[string]types.ImageScanner)
}

// UpdateImageIntegration updates the integration with the matching id to a new configuration.
func (e *setImpl) UpdateImageIntegration(integration *storage.ImageIntegration) (err error) {
	i, err := e.factory.CreateScanner(integration)
	if err != nil {
		return err
	}

	e.lock.Lock()
	defer e.lock.Unlock()
	e.integrations[integration.GetId()] = i
	return
}

// RemoveImageIntegration removes the integration with a matching id if one exists.
func (e *setImpl) RemoveImageIntegration(id string) error {
	e.lock.Lock()
	defer e.lock.Unlock()

	delete(e.integrations, id)
	return nil
}
