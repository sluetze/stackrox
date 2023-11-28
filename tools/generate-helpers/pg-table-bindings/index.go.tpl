
package postgres

import (
    "reflect"
	"time"

	metrics "github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres"
	search "github.com/stackrox/rox/pkg/search"
	pgSearch "github.com/stackrox/rox/pkg/search/postgres"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
)

// NewIndexer returns new indexer for `{{.Type}}`.
func NewIndexer(db postgres.DB) search.Searcher {
	return pgSearch.NewSearcher(db, v1.{{.SearchCategory}}, metricSetIndexOperationDurationTime)
}

func metricSetIndexOperationDurationTime(t time.Time, op ops.Op) {
    metrics.SetIndexOperationDurationTime(t, op, "{{.TrimmedType}}")
}
