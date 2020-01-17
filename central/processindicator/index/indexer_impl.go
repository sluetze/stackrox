package index

import (
	"time"

	metrics "github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	blevehelper "github.com/stackrox/rox/pkg/blevehelper"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	mappings "github.com/stackrox/rox/pkg/search/options/processindicators"
)

const batchSize = 5000

const resourceName = "ProcessIndicator"

type indexerImpl struct {
	index *blevehelper.BleveWrapper
}

type processIndicatorWrapper struct {
	*storage.ProcessIndicator `json:"process_indicator"`
	Type                      string `json:"type"`
}

func (b *indexerImpl) AddProcessIndicator(processindicator *storage.ProcessIndicator) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "ProcessIndicator")
	if err := b.index.Index.Index(processindicator.GetId(), &processIndicatorWrapper{
		ProcessIndicator: processindicator,
		Type:             v1.SearchCategory_PROCESS_INDICATORS.String(),
	}); err != nil {
		return err
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) AddProcessIndicators(processindicators []*storage.ProcessIndicator) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "ProcessIndicator")
	batchManager := batcher.New(len(processindicators), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(processindicators[start:end]); err != nil {
			return err
		}
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) processBatch(processindicators []*storage.ProcessIndicator) error {
	batch := b.index.NewBatch()
	for _, processindicator := range processindicators {
		if err := batch.Index(processindicator.GetId(), &processIndicatorWrapper{
			ProcessIndicator: processindicator,
			Type:             v1.SearchCategory_PROCESS_INDICATORS.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) DeleteProcessIndicator(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "ProcessIndicator")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) DeleteProcessIndicators(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "ProcessIndicator")
	batch := b.index.NewBatch()
	for _, id := range ids {
		batch.Delete(id)
	}
	if err := b.index.Batch(batch); err != nil {
		return err
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) ResetIndex() error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Reset, "ProcessIndicator")
	return blevesearch.ResetIndex(v1.SearchCategory_PROCESS_INDICATORS, b.index.Index)
}

func (b *indexerImpl) Search(q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "ProcessIndicator")
	return blevesearch.RunSearchRequest(v1.SearchCategory_PROCESS_INDICATORS, q, b.index.Index, mappings.OptionsMap, opts...)
}

func (b *indexerImpl) GetTxnCount() uint64 {
	return b.index.GetTxnCount()
}

func (b *indexerImpl) SetTxnCount(seq uint64) error {
	return b.index.SetTxnCount(seq)
}
