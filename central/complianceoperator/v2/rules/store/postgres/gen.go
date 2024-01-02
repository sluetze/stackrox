package postgres

//go:generate pg-table-bindings-wrapper --type=storage.ComplianceOperatorRuleV2 --references=storage.Cluster --feature-flag ComplianceEnhancements
