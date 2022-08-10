// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/search"
)

var (
	// CreateTableNetworkBaselinesStmt holds the create statement for table `network_baselines`.
	CreateTableNetworkBaselinesStmt = &postgres.CreateStmts{
		Table: `
               create table if not exists network_baselines (
                   DeploymentId varchar,
                   ClusterId varchar,
                   Namespace varchar,
                   serialized bytea,
                   PRIMARY KEY(DeploymentId),
                   CONSTRAINT fk_parent_table_0 FOREIGN KEY (ClusterId) REFERENCES clusters(Id) ON DELETE CASCADE
               )
               `,
		GormModel: (*NetworkBaselines)(nil),
		Indexes:   []string{},
		Children:  []*postgres.CreateStmts{},
	}

	// NetworkBaselinesSchema is the go schema for table `network_baselines`.
	NetworkBaselinesSchema = func() *walker.Schema {
		schema := GetSchemaForTable("network_baselines")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.NetworkBaseline)(nil)), "network_baselines")
		referencedSchemas := map[string]*walker.Schema{
			"storage.Cluster": ClustersSchema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory_NETWORK_BASELINE, "networkbaseline", (*storage.NetworkBaseline)(nil)))
		RegisterTable(schema, CreateTableNetworkBaselinesStmt)
		return schema
	}()
)

const (
	NetworkBaselinesTableName = "network_baselines"
)

// NetworkBaselines holds the Gorm model for Postgres table `network_baselines`.
type NetworkBaselines struct {
	DeploymentId string   `gorm:"column:deploymentid;type:varchar;primaryKey"`
	ClusterId    string   `gorm:"column:clusterid;type:varchar"`
	Namespace    string   `gorm:"column:namespace;type:varchar"`
	Serialized   []byte   `gorm:"column:serialized;type:bytea"`
	ClustersRef  Clusters `gorm:"foreignKey:clusterid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}
