package resolvers

import (
	"context"

	"github.com/graph-gophers/graphql-go"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/utils"
)

func init() {
	schema := getBuilder()

	utils.Must(
		schema.AddQuery("policies(query: String): [Policy!]!"),
		schema.AddQuery("policy(id: ID): Policy"),
		schema.AddExtraResolver("Policy", `alerts: [Alert!]!`),
		schema.AddExtraResolver("Policy", `alertsCount: Int`),
	)
}

// Policies returns GraphQL resolvers for all policies
func (resolver *Resolver) Policies(ctx context.Context, args rawQuery) ([]*policyResolver, error) {
	if err := readPolicies(ctx); err != nil {
		return nil, err
	}
	q, err := args.AsV1Query()
	if err != nil {
		return nil, err
	}
	if q == nil {
		return resolver.wrapPolicies(resolver.PolicyDataStore.GetPolicies(ctx))
	}
	return resolver.wrapPolicies(resolver.PolicyDataStore.SearchRawPolicies(ctx, q))
}

// Policy returns a GraphQL resolver for a given policy
func (resolver *Resolver) Policy(ctx context.Context, args struct{ *graphql.ID }) (*policyResolver, error) {
	if err := readPolicies(ctx); err != nil {
		return nil, err
	}
	return resolver.wrapPolicy(resolver.PolicyDataStore.GetPolicy(ctx, string(*args.ID)))
}

// Alerts returns GraphQL resolvers for all alerts for this policy
func (resolver *policyResolver) Alerts(ctx context.Context) ([]*alertResolver, error) {
	if err := readAlerts(ctx); err != nil {
		return nil, err
	}
	query := search.NewQueryBuilder().AddStrings(search.PolicyID, resolver.data.GetId()).ProtoQuery()
	return resolver.root.wrapAlerts(
		resolver.root.ViolationsDataStore.SearchRawAlerts(ctx, query))
}

func (resolver *policyResolver) AlertsCount(ctx context.Context) (*int32, error) {
	if err := readAlerts(ctx); err != nil {
		return nil, err // could return nil, nil to prevent errors from propagating.
	}
	query := search.NewQueryBuilder().AddStrings(search.PolicyID, resolver.data.GetId()).ProtoQuery()
	results, err := resolver.root.ViolationsDataStore.Search(ctx, query)
	if err != nil {
		return nil, err
	}
	l := int32(len(results))
	return &l, nil
}
