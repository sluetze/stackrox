package writer

import (
	"context"

	"github.com/stackrox/rox/central/notifications/datastore/internal/store"
	"github.com/stackrox/rox/generated/storage"
)

// Writer implements a buffered write for the notifications datastore.
//
// When notifications are upserted to the writer, they first end up in a buffer.
// The buffered notification has the most recent notification state. If
// an entry for the notification is already present in the data store, this record
// is merged with the buffered record. The buffer is written to the data store
// once the writer is flushed.
//
//go:generate mockgen-wrapper
type Writer interface {
	Upsert(ctx context.Context, obj *storage.Notification) error
	Flush(ctx context.Context) error
}

// New returns a new writer instance.
func New(store store.Store) Writer {
	return &writerImpl{
		buffer: make(map[string]*storage.Notification),
		store:  store,
	}
}
