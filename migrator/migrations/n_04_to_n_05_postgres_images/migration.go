// Code originally generated by pg-bindings generator.

package n4ton5

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_04_to_n_05_postgres_images/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_04_to_n_05_postgres_images/postgres"
	store "github.com/stackrox/rox/migrator/migrations/n_04_to_n_05_postgres_images/store"
	"github.com/stackrox/rox/migrator/types"
	rawDackbox "github.com/stackrox/rox/pkg/dackbox/raw"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres"
	pkgSchema "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	migration = types.Migration{
		StartingSeqNum: pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres() + 4,
		VersionAfter:   storage.Version{SeqNum: int32(pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres()) + 5},
		Run: func(databases *types.Databases) error {
			legacyStore := legacy.New(rawDackbox.GetGlobalDackBox(), rawDackbox.GetKeyFence(), false)
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving images from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 1000
	schema    = pkgSchema.ImagesSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *postgres.Postgres, legacyStore store.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB, true)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, pkgSchema.ImageComponentsSchema.Table)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, pkgSchema.ImageCvesSchema.Table)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, pkgSchema.ImageCveEdgesSchema.Table)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, pkgSchema.ImageComponentEdgesSchema.Table)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, pkgSchema.ImageComponentCveEdgesSchema.Table)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, schema.Table)
	return walk(ctx, legacyStore, func(obj *storage.Image) error {
		if err := store.Upsert(ctx, obj); err != nil {
			log.WriteToStderrf("failed to persist images to store %v", err)
			return err
		}
		return nil
	})
}

func walk(ctx context.Context, legacyStore store.Store, fn func(obj *storage.Image) error) error {
	ids, err := legacyStore.GetIDs(ctx)
	if err != nil {
		return err
	}

	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize

		if end > len(ids) {
			end = len(ids)
		}
		objs, _, err := legacyStore.GetMany(ctx, ids[i:end])
		if err != nil {
			return err
		}
		for _, obj := range objs {
			if err = fn(obj); err != nil {
				return err
			}
		}
	}
	return nil
}

func init() {
	migrations.MustRegisterMigration(migration)
}
