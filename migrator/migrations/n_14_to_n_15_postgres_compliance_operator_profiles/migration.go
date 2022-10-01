// Code generated by pg-bindings generator. DO NOT EDIT.
package n14ton15

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_14_to_n_15_postgres_compliance_operator_profiles/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_14_to_n_15_postgres_compliance_operator_profiles/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres"
	pkgSchema "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	migration = types.Migration{
		StartingSeqNum: pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres() + 14,
		VersionAfter:   storage.Version{SeqNum: int32(pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres()) + 15},
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving compliance_operator_profiles from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = pkgSchema.ComplianceOperatorProfilesSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *postgres.Postgres, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, schema.Table)
	var complianceOperatorProfiles []*storage.ComplianceOperatorProfile
	err := walk(ctx, legacyStore, func(obj *storage.ComplianceOperatorProfile) error {
		complianceOperatorProfiles = append(complianceOperatorProfiles, obj)
		if len(complianceOperatorProfiles) == batchSize {
			if err := store.UpsertMany(ctx, complianceOperatorProfiles); err != nil {
				log.WriteToStderrf("failed to persist compliance_operator_profiles to store %v", err)
				return err
			}
			complianceOperatorProfiles = complianceOperatorProfiles[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(complianceOperatorProfiles) > 0 {
		if err = store.UpsertMany(ctx, complianceOperatorProfiles); err != nil {
			log.WriteToStderrf("failed to persist compliance_operator_profiles to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.ComplianceOperatorProfile) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}
