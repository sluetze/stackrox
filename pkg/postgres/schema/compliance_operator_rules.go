// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
)

var (
	// CreateTableComplianceOperatorRulesStmt holds the create statement for table `compliance_operator_rules`.
	CreateTableComplianceOperatorRulesStmt = &postgres.CreateStmts{
		Table: `
               create table if not exists compliance_operator_rules (
                   Id varchar,
                   ClusterId varchar,
                   serialized bytea,
                   PRIMARY KEY(Id),
                   CONSTRAINT fk_parent_table_0 FOREIGN KEY (ClusterId) REFERENCES clusters(Id) ON DELETE CASCADE
               )
               `,
		GormModel: (*ComplianceOperatorRules)(nil),
		Indexes:   []string{},
		Children:  []*postgres.CreateStmts{},
	}

	// ComplianceOperatorRulesSchema is the go schema for table `compliance_operator_rules`.
	ComplianceOperatorRulesSchema = func() *walker.Schema {
		schema := GetSchemaForTable("compliance_operator_rules")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.ComplianceOperatorRule)(nil)), "compliance_operator_rules")
		referencedSchemas := map[string]*walker.Schema{
			"storage.Cluster": ClustersSchema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		RegisterTable(schema, CreateTableComplianceOperatorRulesStmt)
		return schema
	}()
)

const (
	ComplianceOperatorRulesTableName = "compliance_operator_rules"
)

// ComplianceOperatorRules holds the Gorm model for Postgres table `compliance_operator_rules`.
type ComplianceOperatorRules struct {
	Id          string   `gorm:"column:id;type:varchar;primaryKey"`
	ClusterId   string   `gorm:"column:clusterid;type:varchar"`
	Serialized  []byte   `gorm:"column:serialized;type:bytea"`
	ClustersRef Clusters `gorm:"foreignKey:clusterid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}
