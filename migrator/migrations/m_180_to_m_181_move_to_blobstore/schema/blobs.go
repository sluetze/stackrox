// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"reflect"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
)

var (
	// CreateTableBlobsStmt holds the create statement for table `blobs`.
	CreateTableBlobsStmt = &postgres.CreateStmts{
		GormModel: (*Blobs)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// BlobsSchema is the go schema for table `blobs`.
	BlobsSchema = func() *walker.Schema {
		schema := walker.Walk(reflect.TypeOf((*storage.Blob)(nil)), "blobs")
		return schema
	}()
)

const (
	BlobsTableName = "blobs"
)

// Blobs holds the Gorm model for Postgres table `blobs`.
type Blobs struct {
	Name       string `gorm:"column:name;type:varchar;primaryKey"`
	Serialized []byte `gorm:"column:serialized;type:bytea"`
}
