// Code originally generated by pg-bindings generator.

package n4ton5

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/dackboxhelper"
	"github.com/stackrox/rox/migrator/migrations"
	frozenSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_04_to_n_05_postgres_images/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_04_to_n_05_postgres_images/postgres"
	store "github.com/stackrox/rox/migrator/migrations/n_04_to_n_05_postgres_images/store"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	startingSeqNum = pkgMigrations.BasePostgresDBVersionSeqNum() + 4 // 115

	migration = types.Migration{
		StartingSeqNum: startingSeqNum,
		VersionAfter:   &storage.Version{SeqNum: int32(startingSeqNum + 1)}, // 116
		Run: func(databases *types.Databases) error {
			legacyStore := legacy.New(dackboxhelper.GetMigrationDackBox(), dackboxhelper.GetMigrationKeyFence(), false)
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving images from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 500
	schema    = frozenSchema.ImagesSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB postgres.DB, legacyStore store.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB, true)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableImageComponentsStmt)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableImageCvesStmt)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableImageCveEdgesStmt)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableImageComponentEdgesStmt)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableImageComponentCveEdgesStmt)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableImagesStmt)
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
