// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"reflect"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/sac/resources"
)

var (
	// CreateTableComplianceOperatorRuleV2Stmt holds the create statement for table `compliance_operator_rule_v2`.
	CreateTableComplianceOperatorRuleV2Stmt = &postgres.CreateStmts{
		GormModel: (*ComplianceOperatorRuleV2)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// ComplianceOperatorRuleV2Schema is the go schema for table `compliance_operator_rule_v2`.
	ComplianceOperatorRuleV2Schema = func() *walker.Schema {
		schema := GetSchemaForTable("compliance_operator_rule_v2")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.ComplianceOperatorRuleV2)(nil)), "compliance_operator_rule_v2")
		schema.ScopingResource = resources.Compliance
		RegisterTable(schema, CreateTableComplianceOperatorRuleV2Stmt, features.ComplianceEnhancements.Enabled)
		return schema
	}()
)

const (
	// ComplianceOperatorRuleV2TableName specifies the name of the table in postgres.
	ComplianceOperatorRuleV2TableName = "compliance_operator_rule_v2"
)

// ComplianceOperatorRuleV2 holds the Gorm model for Postgres table `compliance_operator_rule_v2`.
type ComplianceOperatorRuleV2 struct {
	Name            string               `gorm:"column:name;type:varchar;primaryKey"`
	OperatorVersion string               `gorm:"column:operatorversion;type:varchar"`
	RuleVersion     string               `gorm:"column:ruleversion;type:varchar"`
	RuleType        string               `gorm:"column:ruletype;type:varchar"`
	Severity        storage.RuleSeverity `gorm:"column:severity;type:integer"`
	Serialized      []byte               `gorm:"column:serialized;type:bytea"`
}
