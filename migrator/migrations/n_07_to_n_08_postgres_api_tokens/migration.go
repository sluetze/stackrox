// Code generated by pg-bindings generator. DO NOT EDIT.
package n7ton8

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	frozenSchema "github.com/stackrox/rox/migrator/migrations/frozenschema/v73"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_07_to_n_08_postgres_api_tokens/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_07_to_n_08_postgres_api_tokens/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	startingSeqNum = pkgMigrations.BasePostgresDBVersionSeqNum() + 7 // 118

	migration = types.Migration{
		StartingSeqNum: startingSeqNum,
		VersionAfter:   &storage.Version{SeqNum: int32(startingSeqNum + 1)}, // 119
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving api_tokens from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = frozenSchema.ApiTokensSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *pgxpool.Pool, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pgutils.CreateTableFromModel(context.Background(), gormDB, frozenSchema.CreateTableApiTokensStmt)
	var apiTokens []*storage.TokenMetadata
	err := walk(ctx, legacyStore, func(obj *storage.TokenMetadata) error {
		apiTokens = append(apiTokens, obj)
		if len(apiTokens) == batchSize {
			if err := store.UpsertMany(ctx, apiTokens); err != nil {
				log.WriteToStderrf("failed to persist api_tokens to store %v", err)
				return err
			}
			apiTokens = apiTokens[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(apiTokens) > 0 {
		if err = store.UpsertMany(ctx, apiTokens); err != nil {
			log.WriteToStderrf("failed to persist api_tokens to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.TokenMetadata) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}
