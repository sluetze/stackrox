package store

import (
	"context"
	"io"

	"github.com/jackc/pgx/v4"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/blob/datastore/store/postgres"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	pgPkg "github.com/stackrox/rox/pkg/postgres"
)

var log = logging.LoggerForModule()

// Store is the interface to interact with the storage for storage.Blob
type Store interface {
	Upsert(ctx context.Context, obj *storage.Blob, reader io.Reader) error
	Get(ctx context.Context, name string) (*storage.Blob, io.ReadCloser, bool, error)
	Delete(ctx context.Context, name string) error
}

type storeImpl struct {
	db    pgPkg.DB
	store postgres.Store
}

// New creates a new Blob store
func New(db pgPkg.DB) Store {
	return &storeImpl{
		db:    db,
		store: postgres.New(db),
	}
}

func wrapRollback(ctx context.Context, tx *pgPkg.Tx, err error) error {
	rollbackErr := tx.Rollback(ctx)
	if rollbackErr != nil {
		return errors.Wrapf(rollbackErr, "rolling back due to err: %v", err)
	}
	return err
}

// Upsert adds a blob to the database
func (s *storeImpl) Upsert(ctx context.Context, obj *storage.Blob, reader io.Reader) error {
	existingBlob, exists, err := s.store.Get(ctx, obj.GetName())
	if err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	ctx = pgPkg.ContextWithTx(ctx, tx)

	los := tx.LargeObjects()
	var lo *pgx.LargeObject
	if exists {
		lo, err = los.Open(ctx, existingBlob.GetOid(), pgx.LargeObjectModeWrite)
		if err != nil {
			return wrapRollback(ctx, tx, errors.Wrapf(err, "opening blob with oid %d", existingBlob.GetOid()))
		}
		if err := lo.Truncate(0); err != nil {
			return errors.Wrapf(err, "truncating blob with oid %d", existingBlob.GetOid())
		}
	} else {
		oid, err := los.Create(ctx, 0)
		if err != nil {
			return wrapRollback(ctx, tx, errors.Wrap(err, "error creating new blob"))
		}
		lo, err = los.Open(ctx, oid, pgx.LargeObjectModeWrite)
		if err != nil {
			return wrapRollback(ctx, tx, errors.Wrapf(err, "opening blob with oid %d", oid))
		}
		obj.Oid = oid
	}
	buf := make([]byte, 1024*1024)
	for {
		nRead, err := reader.Read(buf)

		if nRead != 0 {
			if _, err := lo.Write(buf[:nRead]); err != nil {
				return wrapRollback(ctx, tx, errors.Wrap(err, "writing blob"))
			}
		}

		// nRead can be non-zero when err == io.EOF
		if err != nil {
			if err == io.EOF {
				break
			}
			return wrapRollback(ctx, tx, errors.Wrap(err, "reading buffer to write for blob"))
		}
	}
	if err := lo.Close(); err != nil {
		return wrapRollback(ctx, tx, errors.Wrap(err, "closing large object for blob"))
	}

	if err := s.store.Upsert(ctx, obj); err != nil {
		return wrapRollback(ctx, tx, errors.Wrapf(err, "error upserting blob %q", obj.GetName()))
	}
	return tx.Commit(ctx)
}

// Get returns a blob from the database
func (s *storeImpl) Get(ctx context.Context, name string) (*storage.Blob, io.ReadCloser, bool, error) {
	existingBlob, exists, err := s.store.Get(ctx, name)
	if err != nil || !exists {
		return nil, nil, exists, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	ctx = pgPkg.ContextWithTx(ctx, tx)

	los := tx.LargeObjects()
	lo, err := los.Open(ctx, existingBlob.GetOid(), pgx.LargeObjectModeRead)
	if err != nil {
		err := errors.Wrapf(err, "error opening large object with oid %d", existingBlob.GetOid())
		return nil, nil, false, wrapRollback(ctx, tx, err)
	}

	return existingBlob, lo, true, tx.Commit(ctx)
}

// Delete removes a blob store from database
func (s *storeImpl) Delete(ctx context.Context, name string) error {
	existingBlob, exists, err := s.store.Get(ctx, name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}

	ctx = pgPkg.ContextWithTx(ctx, tx)
	los := tx.LargeObjects()
	if err = los.Unlink(ctx, existingBlob.GetOid()); err != nil {
		return errors.Wrapf(err, "failed to remove large object with oid %d", existingBlob.GetOid())
	}
	if err = s.store.Delete(ctx, name); err != nil {
		err = errors.Wrapf(err, "deleting large object %s", name)
		return wrapRollback(ctx, tx, err)
	}

	return tx.Commit(ctx)
}
