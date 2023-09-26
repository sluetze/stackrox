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
	// CreateTableNetworkpolicyapplicationundorecordsStmt holds the create statement for table `networkpolicyapplicationundorecords`.
	CreateTableNetworkpolicyapplicationundorecordsStmt = &postgres.CreateStmts{
		GormModel: (*Networkpolicyapplicationundorecords)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// NetworkpolicyapplicationundorecordsSchema is the go schema for table `networkpolicyapplicationundorecords`.
	NetworkpolicyapplicationundorecordsSchema = func() *walker.Schema {
		schema := GetSchemaForTable("networkpolicyapplicationundorecords")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.NetworkPolicyApplicationUndoRecord)(nil)), "networkpolicyapplicationundorecords")
		schema.ScopingResource = resources.NetworkPolicy
		RegisterTable(schema, CreateTableNetworkpolicyapplicationundorecordsStmt)
		return schema
	}()
)

const (
	// NetworkpolicyapplicationundorecordsTableName specifies the name of the table in postgres.
	NetworkpolicyapplicationundorecordsTableName = "networkpolicyapplicationundorecords"
)

// Networkpolicyapplicationundorecords holds the Gorm model for Postgres table `networkpolicyapplicationundorecords`.
type Networkpolicyapplicationundorecords struct {
	ClusterID  string `gorm:"column:clusterid;type:uuid;primaryKey"`
	Serialized []byte `gorm:"column:serialized;type:bytea"`
	TenantId   string `gorm:"column:tenant_id;type:varchar"`
}
