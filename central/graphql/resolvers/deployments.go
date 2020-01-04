package resolvers

import (
	"context"
	"fmt"
	"time"

	"github.com/graph-gophers/graphql-go"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/graphql/resolvers/loaders"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/central/policy/matcher"
	"github.com/stackrox/rox/central/processindicator/service"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	pkgMetrics "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
)

func init() {
	schema := getBuilder()
	utils.Must(
		schema.AddQuery("deployment(id: ID): Deployment"),
		schema.AddQuery("deployments(query: String, pagination: Pagination): [Deployment!]!"),
		schema.AddQuery("deploymentCount(query: String): Int!"),
		schema.AddExtraResolver("Deployment", `cluster: Cluster`),
		schema.AddExtraResolver("Deployment", `namespaceObject: Namespace`),
		schema.AddExtraResolver("Deployment", `serviceAccountObject: ServiceAccount`),
		schema.AddExtraResolver("Deployment", `groupedProcesses: [ProcessNameGroup!]!`),
		schema.AddExtraResolver("Deployment", `deployAlerts(query: String, pagination: Pagination): [Alert!]!`),
		schema.AddExtraResolver("Deployment", `deployAlertCount(query: String): Int!`),
		schema.AddExtraResolver("Deployment", "latestViolation(query: String): Time"),
		schema.AddExtraResolver("Deployment", "policies(query: String, pagination: Pagination): [Policy!]!"),
		schema.AddExtraResolver("Deployment", "policyCount(query: String): Int!"),
		schema.AddExtraResolver("Deployment", `failingPolicies(query: String, pagination: Pagination): [Policy!]!`),
		schema.AddExtraResolver("Deployment", `failingPolicyCount(query: String): Int!`),
		schema.AddExtraResolver("Deployment", `failingPolicyCounter: PolicyCounter`),
		schema.AddExtraResolver("Deployment", "complianceResults(query: String): [ControlResult!]!"),
		schema.AddExtraResolver("Deployment", "serviceAccountID: String!"),
		schema.AddExtraResolver("Deployment", `images(query: String, pagination: Pagination): [Image!]!`),
		schema.AddExtraResolver("Deployment", `imageCount(query: String): Int!`),
		schema.AddExtraResolver("Deployment", `components(query: String, pagination: Pagination): [EmbeddedImageScanComponent!]!`),
		schema.AddExtraResolver("Deployment", `componentCount(query: String): Int!`),
		schema.AddExtraResolver("Deployment", `vulns(query: String, pagination: Pagination): [EmbeddedVulnerability!]!`),
		schema.AddExtraResolver("Deployment", `vulnCount(query: String): Int!`),
		schema.AddExtraResolver("Deployment", `vulnCounter: VulnerabilityCounter!`),
		schema.AddExtraResolver("Deployment", "secrets(query: String, pagination: Pagination): [Secret!]!"),
		schema.AddExtraResolver("Deployment", "secretCount(query: String): Int!"),
		schema.AddExtraResolver("Deployment", "policyStatus(query: String) : String!"),
	)
}

// Deployment returns a GraphQL resolver for a given id
func (resolver *Resolver) Deployment(ctx context.Context, args struct{ *graphql.ID }) (*deploymentResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "Deployment")
	if err := readDeployments(ctx); err != nil {
		return nil, err
	}
	return resolver.wrapDeployment(resolver.DeploymentDataStore.GetDeployment(ctx, string(*args.ID)))
}

// Deployments returns GraphQL resolvers all deployments
func (resolver *Resolver) Deployments(ctx context.Context, args paginatedQuery) ([]*deploymentResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "Deployments")
	if err := readDeployments(ctx); err != nil {
		return nil, err
	}
	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}
	return resolver.wrapDeployments(
		resolver.DeploymentDataStore.SearchRawDeployments(ctx, q))
}

// DeploymentCount returns count all deployments across infrastructure
func (resolver *Resolver) DeploymentCount(ctx context.Context, args rawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "DeploymentCount")
	if err := readDeployments(ctx); err != nil {
		return 0, err
	}
	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}
	results, err := resolver.DeploymentDataStore.Search(ctx, q)
	if err != nil {
		return 0, err
	}
	return int32(len(results)), nil
}

// Cluster returns a GraphQL resolver for the cluster where this deployment runs
func (resolver *deploymentResolver) Cluster(ctx context.Context) (*clusterResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Cluster")
	if err := readClusters(ctx); err != nil {
		return nil, err
	}

	clusterID := graphql.ID(resolver.data.GetClusterId())
	return resolver.root.Cluster(ctx, struct{ graphql.ID }{clusterID})
}

// NamespaceObject returns a GraphQL resolver for the namespace where this deployment runs
func (resolver *deploymentResolver) NamespaceObject(ctx context.Context) (*namespaceResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "NamespaceObject")

	if err := readNamespaces(ctx); err != nil {
		return nil, err
	}
	namespaceID := graphql.ID(resolver.data.GetNamespaceId())
	return resolver.root.Namespace(ctx, struct{ graphql.ID }{namespaceID})
}

// ServiceAccountObject returns a GraphQL resolver for the service account associated with this deployment
func (resolver *deploymentResolver) ServiceAccountObject(ctx context.Context) (*serviceAccountResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ServiceAccountObject")

	if err := readServiceAccounts(ctx); err != nil {
		return nil, err
	}
	serviceAccountName := resolver.data.GetServiceAccount()
	results, err := resolver.root.ServiceAccountsDataStore.SearchRawServiceAccounts(ctx, search.NewQueryBuilder().AddExactMatches(
		search.ClusterID, resolver.data.GetClusterId()).
		AddExactMatches(search.Namespace, resolver.data.GetNamespace()).
		AddExactMatches(search.ServiceAccountName, serviceAccountName).ProtoQuery())

	if err != nil || results == nil {
		return nil, err
	}

	return resolver.root.wrapServiceAccount(results[0], true, err)
}

func (resolver *deploymentResolver) GroupedProcesses(ctx context.Context) ([]*processNameGroupResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "GroupedProcesses")

	if err := readIndicators(ctx); err != nil {
		return nil, err
	}
	query := search.NewQueryBuilder().AddStrings(search.DeploymentID, resolver.data.GetId()).ProtoQuery()
	indicators, err := resolver.root.ProcessIndicatorStore.SearchRawProcessIndicators(ctx, query)
	return resolver.root.wrapProcessNameGroups(service.IndicatorsToGroupedResponses(indicators), err)
}

func (resolver *deploymentResolver) DeployAlerts(ctx context.Context, args paginatedQuery) ([]*alertResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "DeployAlerts")

	if err := readAlerts(ctx); err != nil {
		return nil, err
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	pagination := q.GetPagination()
	q.Pagination = nil

	nested, err := search.AddAsConjunction(q, resolver.getQuery())
	if err != nil {
		return nil, err
	}

	nested.Pagination = pagination

	return resolver.root.wrapAlerts(
		resolver.root.ViolationsDataStore.SearchRawAlerts(ctx, nested))
}

func (resolver *deploymentResolver) DeployAlertCount(ctx context.Context, args rawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "DeployAlertsCount")

	if err := readAlerts(ctx); err != nil {
		return 0, err // could return nil, nil to prevent errors from propagating.
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}

	q, err = search.AddAsConjunction(resolver.getQuery(), q)
	if err != nil {
		return 0, err
	}

	results, err := resolver.root.ViolationsDataStore.Search(ctx, q)
	if err != nil {
		return 0, err
	}
	return int32(len(results)), nil
}

func (resolver *deploymentResolver) Policies(ctx context.Context, args paginatedQuery) ([]*policyResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Policies")

	if err := readPolicies(ctx); err != nil {
		return nil, err
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	// remove pagination from query since we want to paginate the final result
	pagination := q.GetPagination()
	q.Pagination = &v1.QueryPagination{}

	resolvers, err := paginationWrapper{
		pv: pagination,
	}.paginate(resolver.root.wrapPolicies(resolver.getApplicablePolicies(ctx, q)))
	return resolvers.([]*policyResolver), err
}

func (resolver *deploymentResolver) PolicyCount(ctx context.Context, args rawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "PolicyCount")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}

	policies, err := resolver.getApplicablePolicies(ctx, q)
	if err != nil {
		return 0, err
	}

	return int32(len(policies)), nil
}

func (resolver *deploymentResolver) getApplicablePolicies(ctx context.Context, q *v1.Query) ([]*storage.Policy, error) {
	policyLoader, err := loaders.GetPolicyLoader(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := policyLoader.FromQuery(ctx, q)
	if err != nil {
		return nil, err
	}

	applicable, _ := matcher.NewDeploymentMatcher(resolver.data).FilterApplicablePolicies(policies)
	return applicable, nil
}

// FailingPolicies returns policy resolvers for policies failing on this deployment
func (resolver *deploymentResolver) FailingPolicies(ctx context.Context, args paginatedQuery) ([]*policyResolver, error) {
	if err := readPolicies(ctx); err != nil {
		return nil, err
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	q, err = resolver.getFailingAlertsQuery(q)
	if err != nil {
		return nil, err
	}

	// remove pagination from query since we want to paginate the final result
	pagination := q.GetPagination()
	q.Pagination = &v1.QueryPagination{}

	alerts, err := resolver.root.ViolationsDataStore.SearchRawAlerts(ctx, q)
	if err != nil {
		return nil, err
	}

	var policies []*storage.Policy
	set := set.NewStringSet()
	for _, alert := range alerts {
		if set.Add(alert.GetPolicy().GetId()) {
			policies = append(policies, alert.GetPolicy())
		}
	}

	resolvers, err := paginationWrapper{
		pv: pagination,
	}.paginate(resolver.root.wrapPolicies(policies, nil))
	return resolvers.([]*policyResolver), err
}

// FailingPolicyCount returns count of policies failing on this deployment
func (resolver *deploymentResolver) FailingPolicyCount(ctx context.Context, args rawQuery) (int32, error) {
	if err := readPolicies(ctx); err != nil {
		return 0, err
	}
	query, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}
	query, err = resolver.getFailingAlertsQuery(query)
	if err != nil {
		return 0, err
	}
	alerts, err := resolver.root.ViolationsDataStore.SearchListAlerts(ctx, query)
	if err != nil {
		return 0, nil
	}
	set := set.NewStringSet()
	for _, alert := range alerts {
		set.Add(alert.GetPolicy().GetId())
	}
	return int32(set.Cardinality()), nil
}

// FailingPolicyCounter returns a policy counter for all the failed policies.
func (resolver *deploymentResolver) FailingPolicyCounter(ctx context.Context) (*PolicyCounterResolver, error) {
	if err := readPolicies(ctx); err != nil {
		return nil, err
	}
	query := resolver.getQuery()
	alerts, err := resolver.root.ViolationsDataStore.SearchListAlerts(ctx, query)
	if err != nil {
		return nil, nil
	}
	return mapListAlertsToPolicyCount(alerts), nil
}

// Secrets returns the total number of secrets for this deployment
func (resolver *deploymentResolver) Secrets(ctx context.Context, args paginatedQuery) ([]*secretResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Secrets")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	pagination := q.GetPagination()
	q.Pagination = nil

	secrets, err := resolver.getDeploymentSecrets(ctx, q)
	if err != nil {
		return nil, err
	}

	resolvers, err := paginationWrapper{
		pv: pagination,
	}.paginate(secrets, nil)
	return resolvers.([]*secretResolver), err
}

// SecretCount returns the total number of secrets for this deployment
func (resolver *deploymentResolver) SecretCount(ctx context.Context, args rawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "SecretCount")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}

	secrets, err := resolver.getDeploymentSecrets(ctx, q)
	if err != nil {
		return 0, err
	}

	return int32(len(secrets)), nil
}

func (resolver *deploymentResolver) getDeploymentSecrets(ctx context.Context, q *v1.Query) ([]*secretResolver, error) {
	if err := readSecrets(ctx); err != nil {
		return nil, err
	}
	deployment := resolver.data
	secretSet := set.NewStringSet()
	for _, container := range deployment.GetContainers() {
		for _, secret := range container.GetSecrets() {
			secretSet.Add(secret.GetName())
		}
	}
	if secretSet.Cardinality() == 0 {
		return []*secretResolver{}, nil
	}
	psr := search.NewQueryBuilder().
		AddExactMatches(search.ClusterID, deployment.GetClusterId()).
		AddExactMatches(search.Namespace, deployment.GetNamespace()).
		AddStrings(search.SecretName, secretSet.AsSlice()...).
		ProtoQuery()
	secrets, err := resolver.root.SecretsDataStore.SearchRawSecrets(ctx, psr)
	if err != nil {
		return nil, err
	}
	for _, secret := range secrets {
		resolver.root.getDeploymentRelationships(ctx, secret)
	}
	return resolver.root.wrapSecrets(secrets, nil)
}

func (resolver *Resolver) getDeployment(ctx context.Context, id string) *storage.Deployment {
	deployment, ok, err := resolver.DeploymentDataStore.GetDeployment(ctx, id)
	if err != nil || !ok {
		return nil
	}
	return deployment
}

func (resolver *deploymentResolver) ComplianceResults(ctx context.Context, args rawQuery) ([]*controlResultResolver, error) {
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}

	runResults, err := resolver.root.ComplianceAggregator.GetResultsWithEvidence(ctx, args.String())
	if err != nil {
		return nil, err
	}
	output := newBulkControlResults()
	deploymentID := resolver.data.GetId()
	output.addDeploymentData(resolver.root, runResults, func(d *storage.Deployment, _ *v1.ComplianceControl) bool {
		return d.GetId() == deploymentID
	})

	return *output, nil
}

func (resolver *deploymentResolver) ServiceAccountID(ctx context.Context) (string, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ServiceAccountID")

	if err := readServiceAccounts(ctx); err != nil {
		return "", err
	}

	clusterID := resolver.ClusterId(ctx)
	serviceAccountName := resolver.ServiceAccount(ctx)

	q := search.NewQueryBuilder().
		AddExactMatches(search.ClusterID, clusterID).
		AddExactMatches(search.ServiceAccountName, serviceAccountName).
		ProtoQuery()

	results, err := resolver.root.ServiceAccountsDataStore.Search(ctx, q)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", errors.Wrap(nil, fmt.Sprintf("No matching service accounts found for deployment id: %s", resolver.Id(ctx)))
	}
	return results[0].ID, nil
}

func (resolver *deploymentResolver) Images(ctx context.Context, args paginatedQuery) ([]*imageResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Images")
	if err := readImages(ctx); err != nil {
		return nil, err
	}
	if !resolver.hasImages() {
		return nil, nil
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	pagination := q.Pagination
	q.Pagination = nil

	imageLoader, err := loaders.GetImageLoader(ctx)
	if err != nil {
		return nil, err
	}

	q, err = search.AddAsConjunction(resolver.getImageQuery(ctx), q)
	if err != nil {
		return nil, err
	}

	q.Pagination = pagination

	return resolver.root.wrapImages(imageLoader.FromQuery(ctx, q))
}

func (resolver *deploymentResolver) ImageCount(ctx context.Context, args rawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageCount")
	if err := readImages(ctx); err != nil {
		return 0, err
	}

	query := search.AddRawQueriesAsConjunction(args.String(), resolver.getImageRawQuery(ctx))

	return resolver.root.ImageCount(ctx, rawQuery{Query: &query})
}

func (resolver *deploymentResolver) Components(ctx context.Context, args paginatedQuery) ([]*EmbeddedImageScanComponentResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Cluster, "Components")
	if err := readImages(ctx); err != nil {
		return nil, err
	}
	if !resolver.hasImages() {
		return nil, nil
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	pagination := q.Pagination
	q.Pagination = nil

	q, err = search.AddAsConjunction(resolver.getImageQuery(ctx), q)
	if err != nil {
		return nil, err
	}

	// TODO: Once pagination is implemented on Components DS, remove the wrapper
	resolvers, err := paginationWrapper{
		pv: pagination,
	}.paginate(components(ctx, resolver.root, q))

	return resolvers.([]*EmbeddedImageScanComponentResolver), err
}

func (resolver *deploymentResolver) ComponentCount(ctx context.Context, args rawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Cluster, "ComponentCount")
	if err := readImages(ctx); err != nil {
		return 0, err
	}
	if !resolver.hasImages() {
		return 0, nil
	}
	query, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}
	nested, err := search.AddAsConjunction(resolver.getImageQuery(ctx), query)
	if err != nil {
		return 0, err
	}
	comps, err := components(ctx, resolver.root, nested)
	if err != nil {
		return 0, err
	}
	return int32(len(comps)), nil
}

func (resolver *deploymentResolver) Vulns(ctx context.Context, args paginatedQuery) ([]*EmbeddedVulnerabilityResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Cluster, "Vulns")
	if err := readImages(ctx); err != nil {
		return nil, err
	}
	if !resolver.hasImages() {
		return nil, nil
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	pagination := q.GetPagination()
	q.Pagination = nil

	q, err = search.AddAsConjunction(resolver.getImageQuery(ctx), q)
	if err != nil {
		return nil, err
	}

	// TODO: Once pagination is implemented on CVE DS, remove the wrapper
	resolvers, err := paginationWrapper{
		pv: pagination,
	}.paginate(vulnerabilities(ctx, resolver.root, q))
	return resolvers.([]*EmbeddedVulnerabilityResolver), err
}

func (resolver *deploymentResolver) VulnCount(ctx context.Context, args rawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Cluster, "VulnCount")
	if err := readImages(ctx); err != nil {
		return 0, err
	}
	if !resolver.hasImages() {
		return 0, nil
	}
	query, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}
	nested, err := search.AddAsConjunction(resolver.getImageQuery(ctx), query)
	if err != nil {
		return 0, err
	}
	vulns, err := vulnerabilities(ctx, resolver.root, nested)
	if err != nil {
		return 0, err
	}
	return int32(len(vulns)), nil
}

func (resolver *deploymentResolver) VulnCounter(ctx context.Context) (*VulnerabilityCounterResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Cluster, "VulnCounter")
	if err := readImages(ctx); err != nil {
		return nil, err
	}

	imageShas := resolver.getImageShas(ctx)
	if len(imageShas) == 0 {
		return emptyVulnerabilityCounter(), nil
	}
	imageShaQuery := search.NewQueryBuilder().AddDocIDs(imageShas...).ProtoQuery()
	images, err := resolver.root.ImageDataStore.SearchRawImages(ctx, imageShaQuery)
	if err != nil {
		return nil, err
	}
	return mapImagesToVulnerabilityCounter(images), nil
}

func (resolver *deploymentResolver) PolicyStatus(ctx context.Context, args rawQuery) (string, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "PolicyStatus")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return "", err
	}

	alertExists, err := resolver.unresolvedAlertsExists(ctx, q)
	if err != nil {
		return "", err
	}
	if alertExists {
		return "fail", nil
	}
	return "pass", nil
}

func (resolver *deploymentResolver) hasImages() bool {
	for _, c := range resolver.data.GetContainers() {
		if c.GetImage().GetId() != "" {
			return true
		}
	}
	return false
}

func (resolver *deploymentResolver) getImageShas(ctx context.Context) []string {
	if err := readImages(ctx); err != nil {
		return nil
	}

	imageShas := set.NewStringSet()

	deployment := resolver.data
	containers := deployment.GetContainers()
	for _, c := range containers {
		if c.GetImage().GetId() != "" {
			imageShas.Add(c.GetImage().GetId())
		}
	}
	return imageShas.AsSlice()
}

func (resolver *deploymentResolver) unresolvedAlertsExists(ctx context.Context, q *v1.Query) (bool, error) {
	if err := readAlerts(ctx); err != nil {
		return false, err
	}

	q, err := resolver.getFailingAlertsQuery(q)
	if err != nil {
		return false, err
	}
	q.Pagination = &v1.QueryPagination{Limit: 1}
	results, err := resolver.root.ViolationsDataStore.Search(ctx, q)
	if err != nil {
		return false, err
	}
	return len(results) > 0, nil
}

func (resolver *deploymentResolver) getQuery() *v1.Query {
	return search.NewQueryBuilder().AddExactMatches(search.DeploymentID, resolver.data.GetId()).ProtoQuery()
}

func (resolver *deploymentResolver) getImageQuery(ctx context.Context) *v1.Query {
	imageShas := resolver.getImageShas(ctx)
	if len(imageShas) == 0 {
		return search.EmptyQuery()
	}
	return search.NewQueryBuilder().AddDocIDs(imageShas...).ProtoQuery()
}

func (resolver *deploymentResolver) getImageRawQuery(ctx context.Context) string {
	imageShas := resolver.getImageShas(ctx)
	if len(imageShas) == 0 {
		return ""
	}

	return search.NewQueryBuilder().AddExactMatches(search.ImageSHA, imageShas...).Query()
}

func (resolver *deploymentResolver) getConjunctionQuery(q *v1.Query) (*v1.Query, error) {
	q1 := resolver.getQuery()
	return search.AddAsConjunction(q, q1)
}

func (resolver *deploymentResolver) getFailingAlertsQuery(q *v1.Query) (*v1.Query, error) {
	q, err := resolver.getConjunctionQuery(q)
	if err != nil {
		return nil, err
	}
	return search.NewConjunctionQuery(q, search.NewQueryBuilder().AddExactMatches(search.ViolationState, storage.ViolationState_ACTIVE.String()).ProtoQuery()), nil
}

func (resolver *deploymentResolver) LatestViolation(ctx context.Context, args rawQuery) (*graphql.Time, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Latest Violation")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	q, err = resolver.getConjunctionQuery(q)
	if err != nil {
		return nil, err
	}

	return getLatestViolationTime(ctx, resolver.root, q)
}
