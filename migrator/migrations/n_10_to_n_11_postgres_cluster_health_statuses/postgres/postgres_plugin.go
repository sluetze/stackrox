// This file was originally generated with
// //go:generate cp ../../../../central/cluster/store/clusterhealth/postgres/store.go postgres_plugin.go

package postgres

import (
	"context"

	"github.com/hashicorp/go-multierror"
	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	pkgSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/pkg/logging"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/search"
	pgSearch "github.com/stackrox/rox/pkg/search/postgres"
	"github.com/stackrox/rox/pkg/sync"
)

const (
	baseTable = "cluster_health_statuses"

	batchAfter = 100

	// using copyFrom, we may not even want to batch.  It would probably be simpler
	// to deal with failures if we just sent it all.  Something to think about as we
	// proceed and move into more e2e and larger performance testing
	batchSize = 10000

	cursorBatchSize = 50
	deleteBatchSize = 5000
)

var (
	log    = logging.LoggerForModule()
	schema = pkgSchema.ClusterHealthStatusesSchema
)

// Store for migration
type Store interface {
	Count(ctx context.Context) (int, error)
	Exists(ctx context.Context, id string) (bool, error)
	Get(ctx context.Context, id string) (*storage.ClusterHealthStatus, bool, error)
	GetByQuery(ctx context.Context, query *v1.Query) ([]*storage.ClusterHealthStatus, error)
	Upsert(ctx context.Context, obj *storage.ClusterHealthStatus) error
	UpsertMany(ctx context.Context, objs []*storage.ClusterHealthStatus) error
	Delete(ctx context.Context, id string) error
	DeleteByQuery(ctx context.Context, q *v1.Query) error
	GetIDs(ctx context.Context) ([]string, error)
	GetMany(ctx context.Context, ids []string) ([]*storage.ClusterHealthStatus, []int, error)
	DeleteMany(ctx context.Context, ids []string) error

	Walk(ctx context.Context, fn func(obj *storage.ClusterHealthStatus) error) error

	AckKeysIndexed(ctx context.Context, keys ...string) error
	GetKeysToIndex(ctx context.Context) ([]string, error)
}

type storeImpl struct {
	db    postgres.DB
	mutex sync.Mutex
}

// New returns a new Store instance using the provided sql instance.
func New(db postgres.DB) Store {
	return &storeImpl{
		db: db,
	}
}

func insertIntoClusterHealthStatuses(_ context.Context, batch *pgx.Batch, obj *storage.ClusterHealthStatus) error {

	serialized, marshalErr := obj.Marshal()
	if marshalErr != nil {
		return marshalErr
	}

	if pgutils.NilOrUUID(obj.GetId()) == nil {
		log.Warnf("Id is not a valid uuid -- %v", obj)
		return nil
	}

	values := []interface{}{
		// parent primary keys start
		pgutils.NilOrUUID(obj.GetId()),
		obj.GetSensorHealthStatus(),
		obj.GetCollectorHealthStatus(),
		obj.GetOverallHealthStatus(),
		obj.GetAdmissionControlHealthStatus(),
		obj.GetScannerHealthStatus(),
		pgutils.NilOrTime(obj.GetLastContact()),
		serialized,
	}

	finalStr := "INSERT INTO cluster_health_statuses (Id, SensorHealthStatus, CollectorHealthStatus, OverallHealthStatus, AdmissionControlHealthStatus, ScannerHealthStatus, LastContact, serialized) VALUES($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT(Id) DO UPDATE SET Id = EXCLUDED.Id, SensorHealthStatus = EXCLUDED.SensorHealthStatus, CollectorHealthStatus = EXCLUDED.CollectorHealthStatus, OverallHealthStatus = EXCLUDED.OverallHealthStatus, AdmissionControlHealthStatus = EXCLUDED.AdmissionControlHealthStatus, ScannerHealthStatus = EXCLUDED.ScannerHealthStatus, LastContact = EXCLUDED.LastContact, serialized = EXCLUDED.serialized"
	batch.Queue(finalStr, values...)

	return nil
}

func (s *storeImpl) copyFromClusterHealthStatuses(ctx context.Context, tx *postgres.Tx, objs ...*storage.ClusterHealthStatus) error {

	inputRows := [][]interface{}{}

	var err error

	// This is a copy so first we must delete the rows and re-add them
	// Which is essentially the desired behaviour of an upsert.
	var deletes []string

	copyCols := []string{

		"id",

		"sensorhealthstatus",

		"collectorhealthstatus",

		"overallhealthstatus",

		"admissioncontrolhealthstatus",

		"scannerhealthstatus",

		"lastcontact",

		"serialized",
	}

	for idx, obj := range objs {
		// Todo: ROX-9499 Figure out how to more cleanly template around this issue.
		log.Debugf("This is here for now because there is an issue with pods_TerminatedInstances where the obj in the loop is not used as it only consists of the parent id and the idx.  Putting this here as a stop gap to simply use the object.  %s", obj)

		serialized, marshalErr := obj.Marshal()
		if marshalErr != nil {
			return marshalErr
		}

		if pgutils.NilOrUUID(obj.GetId()) == nil {
			log.Warnf("Id is not a valid uuid -- %v", obj)
			continue
		}
		inputRows = append(inputRows, []interface{}{

			pgutils.NilOrUUID(obj.GetId()),

			obj.GetSensorHealthStatus(),

			obj.GetCollectorHealthStatus(),

			obj.GetOverallHealthStatus(),

			obj.GetAdmissionControlHealthStatus(),

			obj.GetScannerHealthStatus(),

			pgutils.NilOrTime(obj.GetLastContact()),

			serialized,
		})

		// Add the id to be deleted.
		deletes = append(deletes, obj.GetId())

		// if we hit our batch size we need to push the data
		if (idx+1)%batchSize == 0 || idx == len(objs)-1 {
			// copy does not upsert so have to delete first.  parent deletion cascades so only need to
			// delete for the top level parent

			if err := s.DeleteMany(ctx, deletes); err != nil {
				return err
			}
			// clear the inserts and vals for the next batch
			deletes = nil

			_, err = tx.CopyFrom(ctx, pgx.Identifier{"cluster_health_statuses"}, copyCols, pgx.CopyFromRows(inputRows))

			if err != nil {
				return err
			}

			// clear the input rows for the next batch
			inputRows = inputRows[:0]
		}
	}

	return err
}

func (s *storeImpl) copyFrom(ctx context.Context, objs ...*storage.ClusterHealthStatus) error {
	conn, release, err := s.acquireConn(ctx, ops.Get, "ClusterHealthStatus")
	if err != nil {
		return err
	}
	defer release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}

	if err := s.copyFromClusterHealthStatuses(ctx, tx, objs...); err != nil {
		if err := tx.Rollback(ctx); err != nil {
			return err
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func (s *storeImpl) upsert(ctx context.Context, objs ...*storage.ClusterHealthStatus) error {
	conn, release, err := s.acquireConn(ctx, ops.Get, "ClusterHealthStatus")
	if err != nil {
		return err
	}
	defer release()

	for _, obj := range objs {
		batch := &pgx.Batch{}
		if err := insertIntoClusterHealthStatuses(ctx, batch, obj); err != nil {
			return err
		}
		batchResults := conn.SendBatch(ctx, batch)
		var result *multierror.Error
		for i := 0; i < batch.Len(); i++ {
			_, err := batchResults.Exec()
			result = multierror.Append(result, err)
		}
		if err := batchResults.Close(); err != nil {
			return err
		}
		if err := result.ErrorOrNil(); err != nil {
			return err
		}
	}
	return nil
}

func (s *storeImpl) Upsert(ctx context.Context, obj *storage.ClusterHealthStatus) error {

	return pgutils.Retry(func() error {
		return s.upsert(ctx, obj)
	})
}

func (s *storeImpl) UpsertMany(ctx context.Context, objs []*storage.ClusterHealthStatus) error {

	return pgutils.Retry(func() error {
		// Lock since copyFrom requires a delete first before being executed.  If multiple processes are updating
		// same subset of rows, both deletes could occur before the copyFrom resulting in unique constraint
		// violations
		s.mutex.Lock()
		defer s.mutex.Unlock()

		if len(objs) < batchAfter {
			return s.upsert(ctx, objs...)
		}

		return s.copyFrom(ctx, objs...)
	})
}

// Count returns the number of objects in the store
func (s *storeImpl) Count(ctx context.Context) (int, error) {

	var sacQueryFilter *v1.Query

	return pgSearch.RunCountRequestForSchema(ctx, schema, sacQueryFilter, s.db)
}

// Exists returns if the id exists in the store
func (s *storeImpl) Exists(ctx context.Context, id string) (bool, error) {

	var sacQueryFilter *v1.Query

	q := search.ConjunctionQuery(
		sacQueryFilter,
		search.NewQueryBuilder().AddDocIDs(id).ProtoQuery(),
	)

	count, err := pgSearch.RunCountRequestForSchema(ctx, schema, q, s.db)
	// With joins and multiple paths to the scoping resources, it can happen that the Count query for an object identifier
	// returns more than 1, despite the fact that the identifier is unique in the table.
	return count > 0, err
}

// Get returns the object, if it exists from the store
func (s *storeImpl) Get(ctx context.Context, id string) (*storage.ClusterHealthStatus, bool, error) {

	var sacQueryFilter *v1.Query

	q := search.ConjunctionQuery(
		sacQueryFilter,
		search.NewQueryBuilder().AddDocIDs(id).ProtoQuery(),
	)

	data, err := pgSearch.RunGetQueryForSchema[storage.ClusterHealthStatus](ctx, schema, q, s.db)
	if err != nil {
		return nil, false, pgutils.ErrNilIfNoRows(err)
	}

	return data, true, nil
}

func (s *storeImpl) acquireConn(ctx context.Context, _ ops.Op, _ string) (*postgres.Conn, func(), error) {
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn, conn.Release, nil
}

// Delete removes the specified ID from the store
func (s *storeImpl) Delete(ctx context.Context, id string) error {

	var sacQueryFilter *v1.Query

	q := search.ConjunctionQuery(
		sacQueryFilter,
		search.NewQueryBuilder().AddDocIDs(id).ProtoQuery(),
	)

	return pgSearch.RunDeleteRequestForSchema(ctx, schema, q, s.db)
}

// DeleteByQuery removes the objects based on the passed query
func (s *storeImpl) DeleteByQuery(ctx context.Context, query *v1.Query) error {

	var sacQueryFilter *v1.Query

	q := search.ConjunctionQuery(
		sacQueryFilter,
		query,
	)

	return pgSearch.RunDeleteRequestForSchema(ctx, schema, q, s.db)
}

// GetIDs returns all the IDs for the store
func (s *storeImpl) GetIDs(ctx context.Context) ([]string, error) {
	var sacQueryFilter *v1.Query
	result, err := pgSearch.RunSearchRequestForSchema(ctx, schema, sacQueryFilter, s.db)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(result))
	for _, entry := range result {
		ids = append(ids, entry.ID)
	}

	return ids, nil
}

// GetMany returns the objects specified by the IDs or the index in the missing indices slice
func (s *storeImpl) GetMany(ctx context.Context, ids []string) ([]*storage.ClusterHealthStatus, []int, error) {

	if len(ids) == 0 {
		return nil, nil, nil
	}

	var sacQueryFilter *v1.Query
	q := search.ConjunctionQuery(
		sacQueryFilter,
		search.NewQueryBuilder().AddDocIDs(ids...).ProtoQuery(),
	)

	rows, err := pgSearch.RunGetManyQueryForSchema[storage.ClusterHealthStatus](ctx, schema, q, s.db)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			missingIndices := make([]int, 0, len(ids))
			for i := range ids {
				missingIndices = append(missingIndices, i)
			}
			return nil, missingIndices, nil
		}
		return nil, nil, err
	}
	resultsByID := make(map[string]*storage.ClusterHealthStatus, len(rows))
	for _, msg := range rows {
		resultsByID[msg.GetId()] = msg
	}
	missingIndices := make([]int, 0, len(ids)-len(resultsByID))
	// It is important that the elems are populated in the same order as the input ids
	// slice, since some calling code relies on that to maintain order.
	elems := make([]*storage.ClusterHealthStatus, 0, len(resultsByID))
	for i, id := range ids {
		if result, ok := resultsByID[id]; !ok {
			missingIndices = append(missingIndices, i)
		} else {
			elems = append(elems, result)
		}
	}
	return elems, missingIndices, nil
}

// GetByQuery returns the objects matching the query
func (s *storeImpl) GetByQuery(ctx context.Context, query *v1.Query) ([]*storage.ClusterHealthStatus, error) {

	var sacQueryFilter *v1.Query
	q := search.ConjunctionQuery(
		sacQueryFilter,
		query,
	)

	rows, err := pgSearch.RunGetManyQueryForSchema[storage.ClusterHealthStatus](ctx, schema, q, s.db)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// Delete removes the specified IDs from the store
func (s *storeImpl) DeleteMany(ctx context.Context, ids []string) error {

	var sacQueryFilter *v1.Query

	// Batch the deletes
	localBatchSize := deleteBatchSize
	numRecordsToDelete := len(ids)
	for {
		if len(ids) == 0 {
			break
		}

		if len(ids) < localBatchSize {
			localBatchSize = len(ids)
		}

		idBatch := ids[:localBatchSize]
		q := search.ConjunctionQuery(
			sacQueryFilter,
			search.NewQueryBuilder().AddDocIDs(idBatch...).ProtoQuery(),
		)

		if err := pgSearch.RunDeleteRequestForSchema(ctx, schema, q, s.db); err != nil {
			err = errors.Wrapf(err, "unable to delete the records.  Successfully deleted %d out of %d", numRecordsToDelete-len(ids), numRecordsToDelete)
			log.Error(err)
			return err
		}

		// Move the slice forward to start the next batch
		ids = ids[localBatchSize:]
	}

	return nil
}

// Walk iterates over all of the objects in the store and applies the closure
func (s *storeImpl) Walk(ctx context.Context, fn func(obj *storage.ClusterHealthStatus) error) error {
	var sacQueryFilter *v1.Query
	fetcher, closer, err := pgSearch.RunCursorQueryForSchema[storage.ClusterHealthStatus](ctx, schema, sacQueryFilter, s.db)
	if err != nil {
		return err
	}
	defer closer()
	for {
		rows, err := fetcher(cursorBatchSize)
		if err != nil {
			return pgutils.ErrNilIfNoRows(err)
		}
		for _, data := range rows {
			if err := fn(data); err != nil {
				return err
			}
		}
		if len(rows) != cursorBatchSize {
			break
		}
	}
	return nil
}

//// Used for testing

func dropTableClusterHealthStatuses(ctx context.Context, db postgres.DB) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS cluster_health_statuses CASCADE")

}

// Destroy drops the cluster health status table
func Destroy(ctx context.Context, db postgres.DB) {
	dropTableClusterHealthStatuses(ctx, db)
}

//// Stubs for satisfying legacy interfaces

// AckKeysIndexed acknowledges the passed keys were indexed
func (s *storeImpl) AckKeysIndexed(_ context.Context, _ ...string) error {
	return nil
}

// GetKeysToIndex returns the keys that need to be indexed
func (s *storeImpl) GetKeysToIndex(_ context.Context) ([]string, error) {
	return nil, nil
}
