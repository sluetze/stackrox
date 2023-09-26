// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"reflect"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/sac/resources"
)

var (
	// CreateTableInstallationInfosStmt holds the create statement for table `installation_infos`.
	CreateTableInstallationInfosStmt = &postgres.CreateStmts{
		GormModel: (*InstallationInfos)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// InstallationInfosSchema is the go schema for table `installation_infos`.
	InstallationInfosSchema = func() *walker.Schema {
		schema := GetSchemaForTable("installation_infos")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.InstallationInfo)(nil)), "installation_infos")
		schema.ScopingResource = resources.InstallationInfo
		RegisterTable(schema, CreateTableInstallationInfosStmt)
		return schema
	}()
)

const (
	// InstallationInfosTableName specifies the name of the table in postgres.
	InstallationInfosTableName = "installation_infos"
)

// InstallationInfos holds the Gorm model for Postgres table `installation_infos`.
type InstallationInfos struct {
	Serialized []byte `gorm:"column:serialized;type:bytea"`
	TenantId   string `gorm:"column:tenant_id;type:varchar"`
}
