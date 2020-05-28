// Code generated by rocksdb-bindings generator. DO NOT EDIT.

package rocksdb

import (
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/db"
	
	"github.com/stackrox/rox/pkg/rocksdb"
	generic "github.com/stackrox/rox/pkg/rocksdb/crud"
)

var (
	log = logging.LoggerForModule()

	bucket = []byte("alerts")
)

type Store interface {
	Count() (int, error)
	Exists(id string) (bool, error)
	GetIDs() ([]string, error)
	Get(id string) (*storage.Alert, bool, error)
	GetMany(ids []string) ([]*storage.Alert, []int, error)
	Upsert(obj *storage.Alert) error
	UpsertMany(objs []*storage.Alert) error
	Delete(id string) error
	DeleteMany(ids []string) error
	Walk(fn func(obj *storage.Alert) error) error
	AckKeysIndexed(keys ...string) error
	GetKeysToIndex() ([]string, error)
}

type storeImpl struct {
	crud db.Crud
}

func alloc() proto.Message {
	return &storage.Alert{}
}

func keyFunc(msg proto.Message) []byte {
	return []byte(msg.(*storage.Alert).GetId())
}

// New returns a new Store instance using the provided rocksdb instance.

func New(db *rocksdb.RocksDB) Store {
	globaldb.RegisterBucket(bucket, "Alert")
	return &storeImpl{
		crud: generic.NewCRUD(db, bucket, keyFunc, alloc),
	}
}


// Count returns the number of objects in the store
func (b *storeImpl) Count() (int, error) {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.Count, "Alert")

	return b.crud.Count()
}

// Exists returns if the id exists in the store
func (b *storeImpl) Exists(id string) (bool, error) {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.Exists, "Alert")

	return b.crud.Exists(id)
}

// GetIDs returns all the IDs for the store
func (b *storeImpl) GetIDs() ([]string, error) {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.GetAll, "AlertIDs")

	return b.crud.GetKeys()
}

// Get returns the object, if it exists from the store
func (b *storeImpl) Get(id string) (*storage.Alert, bool, error) {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.Get, "Alert")

	msg, exists, err := b.crud.Get(id)
	if err != nil || !exists {
		return nil, false, err
	}
	return msg.(*storage.Alert), true, nil
}

// GetMany returns the objects specified by the IDs or the index in the missing indices slice 
func (b *storeImpl) GetMany(ids []string) ([]*storage.Alert, []int, error) {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.GetMany, "Alert")

	msgs, missingIndices, err := b.crud.GetMany(ids)
	if err != nil {
		return nil, nil, err
	}
	objs := make([]*storage.Alert, 0, len(msgs))
	for _, m := range msgs {
		objs = append(objs, m.(*storage.Alert))
	}
	return objs, missingIndices, nil
}

// Upsert inserts the object into the DB
func (b *storeImpl) Upsert(obj *storage.Alert) error {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.Add, "Alert")

	return b.crud.Upsert(obj)
}

// UpsertMany batches objects into the DB
func (b *storeImpl) UpsertMany(objs []*storage.Alert) error {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.AddMany, "Alert")

	msgs := make([]proto.Message, 0, len(objs))
	for _, o := range objs {
		msgs = append(msgs, o)
    }

	return b.crud.UpsertMany(msgs)
}

// Delete removes the specified ID from the store
func (b *storeImpl) Delete(id string) error {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.Remove, "Alert")

	return b.crud.Delete(id)
}

// Delete removes the specified IDs from the store
func (b *storeImpl) DeleteMany(ids []string) error {
	defer metrics.SetRocksDBOperationDurationTime(time.Now(), ops.RemoveMany, "Alert")

	return b.crud.DeleteMany(ids)
}

// Walk iterates over all of the objects in the store and applies the closure
func (b *storeImpl) Walk(fn func(obj *storage.Alert) error) error {
	return b.crud.Walk(func(msg proto.Message) error {
		return fn(msg.(*storage.Alert))
	})
}

// AckKeysIndexed acknowledges the passed keys were indexed
func (b *storeImpl) AckKeysIndexed(keys ...string) error {
	return b.crud.AckKeysIndexed(keys...)
}

// GetKeysToIndex returns the keys that need to be indexed
func (b *storeImpl) GetKeysToIndex() ([]string, error) {
	return b.crud.GetKeysToIndex()
}
