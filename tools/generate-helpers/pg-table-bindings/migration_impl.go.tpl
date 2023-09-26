{{- define "TODO"}}TODO(do{{- /**/ -}}nt-merge){{- end}}

package {{.packageName}}

import (
	"github.com/pkg/errors"
	"github.com/stackrox/rox/migrator/migrations/{{.migrationDir}}/schema"
	"github.com/stackrox/rox/migrator/types"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
	"gorm.io/gorm/clause"
)

var (
	batchSize = 2000
	log       = logging.LoggerForModule()
)

// {{template "TODO"}}:
//  - remove the gen.go file generated in ../{OBJECT}/store

// {{template "TODO"}}: Determine if this change breaks a previous releases database.
// If so increment the `MinimumSupportedDBVersionSeqNum` to the `CurrentDBVersionSeqNum` of the release immediately
// following the release that cannot tolerate the change in pkg/migrations/internal/fallback_seq_num.go.
//
// For example, in 4.2 a column `column_v2` is added to replace the `column_v1` column in 4.1.
// All the code from 4.2 onward will not reference `column_v1`. At some point in the future a rollback to 4.1
// will not longer be supported and we want to remove `column_v1`. To do so, we will upgrade the schema to remove
// the column and update the `MinimumSupportedDBVersionSeqNum` to be the value of `CurrentDBVersionSeqNum` in 4.2
// as 4.1 will no longer be supported. The migration process will inform the user of an error when trying to migrate
// to a software version that can no longer be supported by the database.

func migrate(database *types.Databases) error {
	// {{template "TODO"}}: Update migration code as required
	// The generated migration handles the simple case of promoting a field to a column on the top level table.  This
	// provides the base.  Enhance and build out to suit the needs of your specific migration case.

	db := database.GormDB
	pgutils.CreateTableFromModel(database.DBCtx, db, schema.CreateTable{{.Table|upperCamelCase}}Stmt)
	db = db.WithContext(database.DBCtx).Table(schema.{{.Table|upperCamelCase}}TableName)

	rows, err := db.Rows()
	if err != nil {
		return errors.Wrapf(err, "failed to iterate table %s", schema.{{.Table|upperCamelCase}}TableName)
	}
	defer func() { _ = rows.Close() }()

	var convertedRecords []*schema.{{.Table|upperCamelCase}}
	var count int
	for rows.Next() {
		var record *schema.{{.Table|upperCamelCase}}
		if err = db.ScanRows(rows, &record); err != nil {
			return errors.Wrap(err, "failed to scan rows")
		}

		recordProto, err := schema.Convert{{.TrimmedType}}ToProto(record)
		if err != nil {
			return errors.Wrapf(err, "failed to convert %+v to proto", record)
		}

		converted, err := schema.Convert{{.TrimmedType}}FromProto(recordProto)
		if err != nil {
			return errors.Wrapf(err, "failed to convert from proto %+v", recordProto)
		}
		convertedRecords = append(convertedRecords, converted)
		count++

		if len(convertedRecords) == batchSize {
			// Upsert converted blobs
			if err = db.Clauses(clause.OnConflict{UpdateAll: true}).Model(schema.CreateTable{{.Table|upperCamelCase}}Stmt.GormModel).Create(&convertedRecords).Error; err != nil {
				return errors.Wrapf(err, "failed to upsert converted %d objects after %d upserted", len(convertedRecords), count-len(convertedRecords))
			}
		convertedRecords = convertedRecords[:0]
		}
	}

	if err := rows.Err(); err != nil {
		return errors.Wrapf(err, "failed to get rows for %s", schema.{{.Table|upperCamelCase}}TableName)
	}

	if len(convertedRecords) > 0 {
		if err = db.Clauses(clause.OnConflict{UpdateAll: true}).Model(schema.CreateTable{{.Table|upperCamelCase}}Stmt.GormModel).Create(&convertedRecords).Error; err != nil {
			return errors.Wrapf(err, "failed to upsert last %d objects", len(convertedRecords))
		}
	}
	log.Infof("Converted %d records", count)

	return nil
}

// {{template "TODO"}}: Write the additional code to support the migration

// {{template "TODO"}}: remove any pending TODO
