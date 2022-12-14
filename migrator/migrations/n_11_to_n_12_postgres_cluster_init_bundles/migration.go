// Code generated by pg-bindings generator. DO NOT EDIT.
package n11ton12

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	frozenSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_11_to_n_12_postgres_cluster_init_bundles/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_11_to_n_12_postgres_cluster_init_bundles/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	startingSeqNum = pkgMigrations.BasePostgresDBVersionSeqNum() + 11 // 122

	migration = types.Migration{
		StartingSeqNum: startingSeqNum,
		VersionAfter:   &storage.Version{SeqNum: int32(startingSeqNum + 1)}, // 123
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving cluster_init_bundles from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = frozenSchema.ClusterInitBundlesSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *pgxpool.Pool, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableClusterInitBundlesStmt)
	var clusterInitBundles []*storage.InitBundleMeta
	err := walk(ctx, legacyStore, func(obj *storage.InitBundleMeta) error {
		clusterInitBundles = append(clusterInitBundles, obj)
		if len(clusterInitBundles) == batchSize {
			if err := store.UpsertMany(ctx, clusterInitBundles); err != nil {
				log.WriteToStderrf("failed to persist cluster_init_bundles to store %v", err)
				return err
			}
			clusterInitBundles = clusterInitBundles[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(clusterInitBundles) > 0 {
		if err = store.UpsertMany(ctx, clusterInitBundles); err != nil {
			log.WriteToStderrf("failed to persist cluster_init_bundles to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.InitBundleMeta) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}
