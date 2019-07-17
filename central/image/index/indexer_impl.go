// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	mappings "github.com/stackrox/rox/central/image/mappings"
	metrics "github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	blevehelper "github.com/stackrox/rox/pkg/blevehelper"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	"time"
)

const batchSize = 5000

const resourceName = "Image"

type indexerImpl struct {
	index *blevehelper.BleveWrapper
}

type imageWrapper struct {
	*storage.Image `json:"image"`
	Type           string `json:"type"`
}

func (b *indexerImpl) AddImage(image *storage.Image) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "Image")
	if err := b.index.Index.Index(image.GetId(), &imageWrapper{
		Image: image,
		Type:  v1.SearchCategory_IMAGES.String(),
	}); err != nil {
		return err
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) AddImages(images []*storage.Image) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "Image")
	batchManager := batcher.New(len(images), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(images[start:end]); err != nil {
			return err
		}
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) processBatch(images []*storage.Image) error {
	batch := b.index.NewBatch()
	for _, image := range images {
		if err := batch.Index(image.GetId(), &imageWrapper{
			Image: image,
			Type:  v1.SearchCategory_IMAGES.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) DeleteImage(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "Image")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) DeleteImages(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "Image")
	batch := b.index.NewBatch()
	for _, id := range ids {
		batch.Delete(id)
	}
	if err := b.index.Batch(batch); err != nil {
		return err
	}
	return b.index.IncTxnCount()
}

func (b *indexerImpl) GetTxnCount() uint64 {
	return b.index.GetTxnCount()
}

func (b *indexerImpl) ResetIndex() error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Reset, "Image")
	return blevesearch.ResetIndex(v1.SearchCategory_IMAGES, b.index.Index)
}

func (b *indexerImpl) Search(q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "Image")
	return blevesearch.RunSearchRequest(v1.SearchCategory_IMAGES, q, b.index.Index, mappings.OptionsMap, opts...)
}

func (b *indexerImpl) SetTxnCount(seq uint64) error {
	return b.index.SetTxnCount(seq)
}
