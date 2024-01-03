package datastore

import (
	"context"

	"github.com/stackrox/rox/central/complianceoperator/v2/rules/store/postgres"
	"github.com/stackrox/rox/generated/storage"
)

type datastoreImpl struct {
	store postgres.Store
}

// UpsertRule adds the rule to the database
func (d *datastoreImpl) UpsertRule(ctx context.Context, rule *storage.ComplianceOperatorRuleV2) error {
	return d.store.Upsert(ctx, rule)
}

// UpsertRules adds the rules to the database
func (d *datastoreImpl) UpsertRules(ctx context.Context, rules []*storage.ComplianceOperatorRuleV2) error {
	return d.store.UpsertMany(ctx, rules)
}

// DeleteRule removes a rule from the database
func (d *datastoreImpl) DeleteRule(ctx context.Context, id string) error {
	return d.store.Delete(ctx, id)
}
