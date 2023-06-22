// Code generated by pg-bindings generator. DO NOT EDIT.

package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/jackc/pgx/v4"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/central/role/resources"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	pkgSchema "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/sac"
	pgSearch "github.com/stackrox/rox/pkg/search/postgres"
	"github.com/stackrox/rox/pkg/sync"
	"gorm.io/gorm"
)

const (
	baseTable = "compliance_run_metadata"

	batchAfter = 100

	// using copyFrom, we may not even want to batch.  It would probably be simpler
	// to deal with failures if we just sent it all.  Something to think about as we
	// proceed and move into more e2e and larger performance testing
	batchSize = 10000
)

var (
	log            = logging.LoggerForModule()
	schema         = pkgSchema.ComplianceRunMetadataSchema
	targetResource = resources.Compliance
)

// Store is the interface to interact with the storage for storage.ComplianceRunMetadata
type Store interface {
	Upsert(ctx context.Context, obj *storage.ComplianceRunMetadata) error
	UpsertMany(ctx context.Context, objs []*storage.ComplianceRunMetadata) error
	Delete(ctx context.Context, runID string) error
	DeleteByQuery(ctx context.Context, q *v1.Query) error
	DeleteMany(ctx context.Context, identifiers []string) error

	Count(ctx context.Context) (int, error)
	Exists(ctx context.Context, runID string) (bool, error)

	Get(ctx context.Context, runID string) (*storage.ComplianceRunMetadata, bool, error)
	GetByQuery(ctx context.Context, query *v1.Query) ([]*storage.ComplianceRunMetadata, error)
	GetMany(ctx context.Context, identifiers []string) ([]*storage.ComplianceRunMetadata, []int, error)
	GetIDs(ctx context.Context) ([]string, error)

	Walk(ctx context.Context, fn func(obj *storage.ComplianceRunMetadata) error) error
}

type storeImpl struct {
	*pgSearch.GenericSingleIDStore[storage.ComplianceRunMetadata, *storage.ComplianceRunMetadata]
	db    postgres.DB
	mutex sync.RWMutex
}

// New returns a new Store instance using the provided sql instance.
func New(db postgres.DB) Store {
	return &storeImpl{
		GenericSingleIDStore: pgSearch.NewGenericSingleIDStore[storage.ComplianceRunMetadata, *storage.ComplianceRunMetadata](
			db,
			targetResource,
			schema,
			metricsSetPostgresOperationDurationTime,
			pkGetter,
		),
		db: db,
	}
}

//// Helper functions

func pkGetter(obj *storage.ComplianceRunMetadata) string {
	return obj.GetRunId()
}

func metricsSetPostgresOperationDurationTime(start time.Time, op ops.Op) {
	metrics.SetPostgresOperationDurationTime(start, op, "ComplianceRunMetadata")
}

func insertIntoComplianceRunMetadata(_ context.Context, batch *pgx.Batch, obj *storage.ComplianceRunMetadata) error {

	serialized, marshalErr := obj.Marshal()
	if marshalErr != nil {
		return marshalErr
	}

	values := []interface{}{
		// parent primary keys start
		obj.GetRunId(),
		obj.GetStandardId(),
		pgutils.NilOrUUID(obj.GetClusterId()),
		pgutils.NilOrTime(obj.GetFinishTimestamp()),
		serialized,
	}

	finalStr := "INSERT INTO compliance_run_metadata (RunId, StandardId, ClusterId, FinishTimestamp, serialized) VALUES($1, $2, $3, $4, $5) ON CONFLICT(RunId) DO UPDATE SET RunId = EXCLUDED.RunId, StandardId = EXCLUDED.StandardId, ClusterId = EXCLUDED.ClusterId, FinishTimestamp = EXCLUDED.FinishTimestamp, serialized = EXCLUDED.serialized"
	batch.Queue(finalStr, values...)

	return nil
}

func (s *storeImpl) copyFromComplianceRunMetadata(ctx context.Context, tx *postgres.Tx, objs ...*storage.ComplianceRunMetadata) error {

	inputRows := [][]interface{}{}

	var err error

	// This is a copy so first we must delete the rows and re-add them
	// Which is essentially the desired behaviour of an upsert.
	var deletes []string

	copyCols := []string{

		"runid",

		"standardid",

		"clusterid",

		"finishtimestamp",

		"serialized",
	}

	for idx, obj := range objs {
		// Todo: ROX-9499 Figure out how to more cleanly template around this issue.
		log.Debugf("This is here for now because there is an issue with pods_TerminatedInstances where the obj "+
			"in the loop is not used as it only consists of the parent ID and the index.  Putting this here as a stop gap "+
			"to simply use the object.  %s", obj)

		serialized, marshalErr := obj.Marshal()
		if marshalErr != nil {
			return marshalErr
		}

		inputRows = append(inputRows, []interface{}{

			obj.GetRunId(),

			obj.GetStandardId(),

			pgutils.NilOrUUID(obj.GetClusterId()),

			pgutils.NilOrTime(obj.GetFinishTimestamp()),

			serialized,
		})

		// Add the ID to be deleted.
		deletes = append(deletes, obj.GetRunId())

		// if we hit our batch size we need to push the data
		if (idx+1)%batchSize == 0 || idx == len(objs)-1 {
			// copy does not upsert so have to delete first.  parent deletion cascades so only need to
			// delete for the top level parent

			if err := s.DeleteMany(ctx, deletes); err != nil {
				return err
			}
			// clear the inserts and vals for the next batch
			deletes = nil

			_, err = tx.CopyFrom(ctx, pgx.Identifier{"compliance_run_metadata"}, copyCols, pgx.CopyFromRows(inputRows))

			if err != nil {
				return err
			}

			// clear the input rows for the next batch
			inputRows = inputRows[:0]
		}
	}

	return err
}

func (s *storeImpl) acquireConn(ctx context.Context, op ops.Op, typ string) (*postgres.Conn, func(), error) {
	defer metrics.SetAcquireDBConnDuration(time.Now(), op, typ)
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn, conn.Release, nil
}

func (s *storeImpl) copyFrom(ctx context.Context, objs ...*storage.ComplianceRunMetadata) error {
	conn, release, err := s.acquireConn(ctx, ops.Get, "ComplianceRunMetadata")
	if err != nil {
		return err
	}
	defer release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}

	if err := s.copyFromComplianceRunMetadata(ctx, tx, objs...); err != nil {
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

func (s *storeImpl) upsert(ctx context.Context, objs ...*storage.ComplianceRunMetadata) error {
	conn, release, err := s.acquireConn(ctx, ops.Get, "ComplianceRunMetadata")
	if err != nil {
		return err
	}
	defer release()

	for _, obj := range objs {
		batch := &pgx.Batch{}
		if err := insertIntoComplianceRunMetadata(ctx, batch, obj); err != nil {
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

//// Helper functions - END

//// Interface functions

// Upsert saves the current state of an object in storage.
func (s *storeImpl) Upsert(ctx context.Context, obj *storage.ComplianceRunMetadata) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.Upsert, "ComplianceRunMetadata")

	scopeChecker := sac.GlobalAccessScopeChecker(ctx).AccessMode(storage.Access_READ_WRITE_ACCESS).Resource(targetResource).
		ClusterID(obj.GetClusterId())
	if !scopeChecker.IsAllowed() {
		return sac.ErrResourceAccessDenied
	}

	return pgutils.Retry(func() error {
		return s.upsert(ctx, obj)
	})
}

// UpsertMany saves the state of multiple objects in the storage.
func (s *storeImpl) UpsertMany(ctx context.Context, objs []*storage.ComplianceRunMetadata) error {
	defer metrics.SetPostgresOperationDurationTime(time.Now(), ops.UpdateMany, "ComplianceRunMetadata")

	scopeChecker := sac.GlobalAccessScopeChecker(ctx).AccessMode(storage.Access_READ_WRITE_ACCESS).Resource(targetResource)
	if !scopeChecker.IsAllowed() {
		var deniedIDs []string
		for _, obj := range objs {
			subScopeChecker := scopeChecker.ClusterID(obj.GetClusterId())
			if !subScopeChecker.IsAllowed() {
				deniedIDs = append(deniedIDs, obj.GetRunId())
			}
		}
		if len(deniedIDs) != 0 {
			return errors.Wrapf(sac.ErrResourceAccessDenied, "modifying complianceRunMetadatas with IDs [%s] was denied", strings.Join(deniedIDs, ", "))
		}
	}

	return pgutils.Retry(func() error {
		// Lock since copyFrom requires a delete first before being executed.  If multiple processes are updating
		// same subset of rows, both deletes could occur before the copyFrom resulting in unique constraint
		// violations
		if len(objs) < batchAfter {
			s.mutex.RLock()
			defer s.mutex.RUnlock()

			return s.upsert(ctx, objs...)
		}
		s.mutex.Lock()
		defer s.mutex.Unlock()

		return s.copyFrom(ctx, objs...)
	})
}

//// Stubs for satisfying legacy interfaces

//// Interface functions - END

//// Used for testing

// CreateTableAndNewStore returns a new Store instance for testing.
func CreateTableAndNewStore(ctx context.Context, db postgres.DB, gormDB *gorm.DB) Store {
	pkgSchema.ApplySchemaForTable(ctx, gormDB, baseTable)
	return New(db)
}

// Destroy drops the tables associated with the target object type.
func Destroy(ctx context.Context, db postgres.DB) {
	dropTableComplianceRunMetadata(ctx, db)
}

func dropTableComplianceRunMetadata(ctx context.Context, db postgres.DB) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS compliance_run_metadata CASCADE")

}

//// Used for testing - END
