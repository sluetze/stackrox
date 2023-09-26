// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/postgres/mapping"
)

var (
	// CreateTableActiveComponentsStmt holds the create statement for table `active_components`.
	CreateTableActiveComponentsStmt = &postgres.CreateStmts{
		GormModel: (*ActiveComponents)(nil),
		Children: []*postgres.CreateStmts{
			&postgres.CreateStmts{
				GormModel: (*ActiveComponentsActiveContextsSlices)(nil),
				Children:  []*postgres.CreateStmts{},
			},
		},
	}

	// ActiveComponentsSchema is the go schema for table `active_components`.
	ActiveComponentsSchema = func() *walker.Schema {
		schema := GetSchemaForTable("active_components")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.ActiveComponent)(nil)), "active_components")
		referencedSchemas := map[string]*walker.Schema{
			"storage.Deployment":     DeploymentsSchema,
			"storage.ImageComponent": ImageComponentsSchema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory_ACTIVE_COMPONENT, "activecomponent", (*storage.ActiveComponent)(nil)))
		schema.ScopingResource = resources.Deployment
		RegisterTable(schema, CreateTableActiveComponentsStmt)
		mapping.RegisterCategoryToTable(v1.SearchCategory_ACTIVE_COMPONENT, schema)
		return schema
	}()
)

const (
	// ActiveComponentsTableName specifies the name of the table in postgres.
	ActiveComponentsTableName = "active_components"
	// ActiveComponentsActiveContextsSlicesTableName specifies the name of the table in postgres.
	ActiveComponentsActiveContextsSlicesTableName = "active_components_active_contexts_slices"
)

// ActiveComponents holds the Gorm model for Postgres table `active_components`.
type ActiveComponents struct {
	ID           string `gorm:"column:id;type:varchar;primaryKey"`
	DeploymentID string `gorm:"column:deploymentid;type:uuid;index:activecomponents_deploymentid,type:hash"`
	ComponentID  string `gorm:"column:componentid;type:varchar"`
	Serialized   []byte `gorm:"column:serialized;type:bytea"`
	TenantId     string `gorm:"column:tenant_id;type:varchar"`
}

// ActiveComponentsActiveContextsSlices holds the Gorm model for Postgres table `active_components_active_contexts_slices`.
type ActiveComponentsActiveContextsSlices struct {
	ActiveComponentsID  string           `gorm:"column:active_components_id;type:varchar;primaryKey"`
	Idx                 int              `gorm:"column:idx;type:integer;primaryKey;index:activecomponentsactivecontextsslices_idx,type:btree"`
	ContainerName       string           `gorm:"column:containername;type:varchar"`
	ImageID             string           `gorm:"column:imageid;type:varchar"`
	ActiveComponentsRef ActiveComponents `gorm:"foreignKey:active_components_id;references:id;belongsTo;constraint:OnDelete:CASCADE"`
	TenantId            string           `gorm:"column:tenant_id;type:varchar"`
}
