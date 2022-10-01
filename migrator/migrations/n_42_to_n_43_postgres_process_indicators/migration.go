// Code generated by pg-bindings generator. DO NOT EDIT.
package n42ton43

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_42_to_n_43_postgres_process_indicators/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_42_to_n_43_postgres_process_indicators/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres"
	pkgSchema "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	migration = types.Migration{
		StartingSeqNum: pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres() + 42,
		VersionAfter:   storage.Version{SeqNum: int32(pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres()) + 43},
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving process_indicators from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = pkgSchema.ProcessIndicatorsSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *postgres.Postgres, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, schema.Table)
	var processIndicators []*storage.ProcessIndicator
	err := walk(ctx, legacyStore, func(obj *storage.ProcessIndicator) error {
		processIndicators = append(processIndicators, obj)
		if len(processIndicators) == batchSize {
			if err := store.UpsertMany(ctx, processIndicators); err != nil {
				log.WriteToStderrf("failed to persist process_indicators to store %v", err)
				return err
			}
			processIndicators = processIndicators[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(processIndicators) > 0 {
		if err = store.UpsertMany(ctx, processIndicators); err != nil {
			log.WriteToStderrf("failed to persist process_indicators to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.ProcessIndicator) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}
