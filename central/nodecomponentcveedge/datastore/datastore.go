package datastore

import (
	"context"
	"testing"

	"github.com/stackrox/rox/central/nodecomponentcveedge/datastore/index"
	"github.com/stackrox/rox/central/nodecomponentcveedge/datastore/search"
	pgStore "github.com/stackrox/rox/central/nodecomponentcveedge/datastore/store/postgres"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	searchPkg "github.com/stackrox/rox/pkg/search"
)

// DataStore is an intermediary to Component/CVE edge storage.
//
//go:generate mockgen-wrapper
type DataStore interface {
	Search(ctx context.Context, q *v1.Query) ([]searchPkg.Result, error)
	SearchEdges(ctx context.Context, q *v1.Query) ([]*v1.SearchResult, error)
	SearchRawEdges(ctx context.Context, q *v1.Query) ([]*storage.NodeComponentCVEEdge, error)

	Exists(ctx context.Context, id string) (bool, error)
	Get(ctx context.Context, id string) (*storage.NodeComponentCVEEdge, bool, error)
	Count(ctx context.Context, q *v1.Query) (int, error)
}

// New returns a new instance of a DataStore.
func New(storage pgStore.Store, indexer index.Indexer, searcher search.Searcher) DataStore {
	ds := &datastoreImpl{
		storage:  storage,
		indexer:  indexer,
		searcher: searcher,
	}
	return ds
}

// GetTestPostgresDataStore provides a datastore connected to postgres for testing purposes.
func GetTestPostgresDataStore(_ testing.TB, pool postgres.DB) DataStore {
	dbstore := pgStore.New(pool)
	indexer := pgStore.NewIndexer(pool)
	searcher := search.New(dbstore, indexer)
	return New(dbstore, indexer, searcher)
}
