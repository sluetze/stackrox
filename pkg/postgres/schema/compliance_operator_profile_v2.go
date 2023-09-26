// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	"github.com/lib/pq"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/sac/resources"
)

var (
	// CreateTableComplianceOperatorProfileV2Stmt holds the create statement for table `compliance_operator_profile_v2`.
	CreateTableComplianceOperatorProfileV2Stmt = &postgres.CreateStmts{
		GormModel: (*ComplianceOperatorProfileV2)(nil),
		Children: []*postgres.CreateStmts{
			&postgres.CreateStmts{
				GormModel: (*ComplianceOperatorProfileV2Rules)(nil),
				Children:  []*postgres.CreateStmts{},
			},
		},
	}

	// ComplianceOperatorProfileV2Schema is the go schema for table `compliance_operator_profile_v2`.
	ComplianceOperatorProfileV2Schema = func() *walker.Schema {
		schema := GetSchemaForTable("compliance_operator_profile_v2")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.ComplianceOperatorProfileV2)(nil)), "compliance_operator_profile_v2")
		referencedSchemas := map[string]*walker.Schema{
			"storage.ComplianceOperatorRuleV2": ComplianceOperatorRuleV2Schema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.ScopingResource = resources.ComplianceOperator
		RegisterTable(schema, CreateTableComplianceOperatorProfileV2Stmt, features.ComplianceEnhancements.Enabled)
		return schema
	}()
)

const (
	// ComplianceOperatorProfileV2TableName specifies the name of the table in postgres.
	ComplianceOperatorProfileV2TableName = "compliance_operator_profile_v2"
	// ComplianceOperatorProfileV2RulesTableName specifies the name of the table in postgres.
	ComplianceOperatorProfileV2RulesTableName = "compliance_operator_profile_v2_rules"
)

// ComplianceOperatorProfileV2 holds the Gorm model for Postgres table `compliance_operator_profile_v2`.
type ComplianceOperatorProfileV2 struct {
	ID          string          `gorm:"column:id;type:varchar;primaryKey"`
	Name        string          `gorm:"column:name;type:varchar;uniqueIndex:rule_unique_indicator"`
	Version     string          `gorm:"column:version;type:varchar;uniqueIndex:rule_unique_indicator"`
	ProductType *pq.StringArray `gorm:"column:producttype;type:text[]"`
	Standard    string          `gorm:"column:standard;type:varchar"`
	Product     string          `gorm:"column:product;type:varchar"`
	Serialized  []byte          `gorm:"column:serialized;type:bytea"`
	TenantId    string          `gorm:"column:tenant_id;type:varchar"`
}

// ComplianceOperatorProfileV2Rules holds the Gorm model for Postgres table `compliance_operator_profile_v2_rules`.
type ComplianceOperatorProfileV2Rules struct {
	ComplianceOperatorProfileV2ID  string                      `gorm:"column:compliance_operator_profile_v2_id;type:varchar;primaryKey"`
	Idx                            int                         `gorm:"column:idx;type:integer;primaryKey;index:complianceoperatorprofilev2rules_idx,type:btree"`
	RuleName                       string                      `gorm:"column:rulename;type:varchar"`
	ComplianceOperatorProfileV2Ref ComplianceOperatorProfileV2 `gorm:"foreignKey:compliance_operator_profile_v2_id;references:id;belongsTo;constraint:OnDelete:CASCADE"`
	TenantId                       string                      `gorm:"column:tenant_id;type:varchar"`
}
