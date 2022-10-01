// Code generated by pg-bindings generator. DO NOT EDIT.
package n18ton19

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_18_to_n_19_postgres_compliance_run_metadata/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_18_to_n_19_postgres_compliance_run_metadata/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres"
	pkgSchema "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	migration = types.Migration{
		StartingSeqNum: pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres() + 18,
		VersionAfter:   storage.Version{SeqNum: int32(pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres()) + 19},
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving compliance_run_metadata from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = pkgSchema.ComplianceRunMetadataSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *postgres.Postgres, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, schema.Table)
	var complianceRunMetadata []*storage.ComplianceRunMetadata
	err := walk(ctx, legacyStore, func(obj *storage.ComplianceRunMetadata) error {
		complianceRunMetadata = append(complianceRunMetadata, obj)
		if len(complianceRunMetadata) == batchSize {
			if err := store.UpsertMany(ctx, complianceRunMetadata); err != nil {
				log.WriteToStderrf("failed to persist compliance_run_metadata to store %v", err)
				return err
			}
			complianceRunMetadata = complianceRunMetadata[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(complianceRunMetadata) > 0 {
		if err = store.UpsertMany(ctx, complianceRunMetadata); err != nil {
			log.WriteToStderrf("failed to persist compliance_run_metadata to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.ComplianceRunMetadata) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}
