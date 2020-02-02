package datastore

import (
	"github.com/stackrox/rox/central/componentcveedge/index"
	"github.com/stackrox/rox/central/componentcveedge/search"
	"github.com/stackrox/rox/central/componentcveedge/store/dackbox"
	globaldb "github.com/stackrox/rox/central/globaldb/dackbox"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	once sync.Once

	ad DataStore
)

func initialize() {
	if !features.Dackbox.Enabled() {
		ad = nil
		return
	}
	storage, err := dackbox.New(globaldb.GetGlobalDackBox())
	utils.Must(err)

	searcher := search.New(storage, index.Singleton())

	ad, err = New(storage, index.Singleton(), searcher)
	utils.Must(err)
}

// Singleton provides the interface for non-service external interaction.
func Singleton() DataStore {
	once.Do(initialize)
	return ad
}
