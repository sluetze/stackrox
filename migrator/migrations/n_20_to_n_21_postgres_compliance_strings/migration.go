// Code generated by pg-bindings generator. DO NOT EDIT.
package n20ton21

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	frozenSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_20_to_n_21_postgres_compliance_strings/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_20_to_n_21_postgres_compliance_strings/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	startingSeqNum = pkgMigrations.BasePostgresDBVersionSeqNum() + 20 // 131

	migration = types.Migration{
		StartingSeqNum: startingSeqNum,
		VersionAfter:   &storage.Version{SeqNum: int32(startingSeqNum + 1)}, // 132
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving compliance_strings from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = frozenSchema.ComplianceStringsSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB postgres.DB, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableComplianceStringsStmt)
	var complianceStrings []*storage.ComplianceStrings
	err := walk(ctx, legacyStore, func(obj *storage.ComplianceStrings) error {
		complianceStrings = append(complianceStrings, obj)
		if len(complianceStrings) == batchSize {
			if err := store.UpsertMany(ctx, complianceStrings); err != nil {
				log.WriteToStderrf("failed to persist compliance_strings to store %v", err)
				return err
			}
			complianceStrings = complianceStrings[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(complianceStrings) > 0 {
		if err = store.UpsertMany(ctx, complianceStrings); err != nil {
			log.WriteToStderrf("failed to persist compliance_strings to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.ComplianceStrings) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}
