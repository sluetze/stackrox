package datastore

import (
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/globalindex"
	"github.com/stackrox/rox/central/risk/datastore/internal/index"
	"github.com/stackrox/rox/central/risk/datastore/internal/search"
	"github.com/stackrox/rox/central/risk/datastore/internal/store"
	pgStore "github.com/stackrox/rox/central/risk/datastore/internal/store/postgres"
	pgIndex "github.com/stackrox/rox/central/risk/datastore/internal/index/postgres"
	"github.com/stackrox/rox/central/risk/datastore/internal/store/rocksdb"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/sync"
)

var (
	once sync.Once

	ad DataStore

	log = logging.LoggerForModule()
)

func initialize() {
	var storage store.Store
	var indexer index.Indexer
	if features.PostgresPOC.Enabled() {
		storage = pgStore.New(globaldb.GetPostgresDB())
		indexer = pgIndex.NewIndexer(globaldb.GetPostgresDB())
	} else {
		storage = rocksdb.New(globaldb.GetRocksDB())
		indexer = index.New(globalindex.GetGlobalTmpIndex())
	}
	var err error
	ad, err = New(storage, indexer, search.New(storage, indexer))
	if err != nil {
		log.Panicf("Failed to initialize risks datastore: %s", err)
	}
}

// Singleton provides the interface for non-service external interaction.
func Singleton() DataStore {
	once.Do(initialize)
	return ad
}
