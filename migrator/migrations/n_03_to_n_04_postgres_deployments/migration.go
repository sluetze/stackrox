// Code generated by pg-bindings generator. DO NOT EDIT.
package n3ton4

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	frozenSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_03_to_n_04_postgres_deployments/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_03_to_n_04_postgres_deployments/postgres"
	"github.com/stackrox/rox/migrator/types"
	rawDackbox "github.com/stackrox/rox/pkg/dackbox/raw"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	startingSeqNum = pkgMigrations.BasePostgresDBVersionSeqNum() + 3 // 114

	migration = types.Migration{
		StartingSeqNum: startingSeqNum,
		VersionAfter:   &storage.Version{SeqNum: int32(startingSeqNum + 1)}, // 115
		Run: func(databases *types.Databases) error {
			legacyStore := legacy.New(rawDackbox.GetGlobalDackBox(), rawDackbox.GetKeyFence())
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving deployments from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = frozenSchema.DeploymentsSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *pgxpool.Pool, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableDeploymentsStmt)
	var deployments []*storage.Deployment
	err := walk(ctx, legacyStore, func(obj *storage.Deployment) error {
		deployments = append(deployments, obj)
		if len(deployments) == batchSize {
			if err := store.UpsertMany(ctx, deployments); err != nil {
				log.WriteToStderrf("failed to persist deployments to store %v", err)
				return err
			}
			deployments = deployments[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(deployments) > 0 {
		if err = store.UpsertMany(ctx, deployments); err != nil {
			log.WriteToStderrf("failed to persist deployments to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.Deployment) error) error {
	return store_walk(ctx, s, fn)
}

func store_walk(ctx context.Context, s legacy.Store, fn func(obj *storage.Deployment) error) error {
	ids, err := s.GetIDs(ctx)
	if err != nil {
		return err
	}

	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize

		if end > len(ids) {
			end = len(ids)
		}
		objs, _, err := s.GetMany(ctx, ids[i:end])
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
