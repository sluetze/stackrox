package blevesearch

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/search/query"
	"github.com/stackrox/rox/generated/api/v1"
)

const (
	negationPrefix = "!"
	nullString     = "-"
	regexPrefix    = "/"
)

var datatypeToQueryFunc = map[v1.SearchDataType]func(v1.SearchCategory, string, string) (query.Query, error){
	v1.SearchDataType_SEARCH_STRING:   newStringQuery,
	v1.SearchDataType_SEARCH_BOOL:     newBoolQuery,
	v1.SearchDataType_SEARCH_NUMERIC:  newNumericQuery,
	v1.SearchDataType_SEARCH_DATETIME: newTimeQuery,

	v1.SearchDataType_SEARCH_SEVERITY:    newSeverityQuery,
	v1.SearchDataType_SEARCH_ENFORCEMENT: newEnforcementQuery,
}

func getWildcardQuery(field string) *query.WildcardQuery {
	wq := bleve.NewWildcardQuery("*")
	wq.SetField(field)
	return wq
}

func evaluateQuery(category v1.SearchCategory, searchField *v1.SearchField, values []string) (query.Query, error) {
	queryFunc, ok := datatypeToQueryFunc[searchField.GetType()]
	if !ok {
		return nil, fmt.Errorf("Query for type %s is not implemented", searchField.GetType())
	}

	d := bleve.NewDisjunctionQuery()
	for _, val := range values {
		// Special case: null
		if val == nullString {
			bq := bleve.NewBooleanQuery()
			bq.AddMustNot(getWildcardQuery(searchField.GetFieldPath()))
			bq.AddMust(typeQuery(category))
			d.AddQuery(bq)
			continue
		}
		q, err := queryFunc(category, searchField.GetFieldPath(), val)
		if err != nil {
			return nil, err
		}
		d.AddQuery(q)
	}
	return d, nil
}

func newStringQuery(category v1.SearchCategory, field string, value string) (query.Query, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("Value in search query cannot be empty")
	}
	switch {
	case strings.HasPrefix(value, negationPrefix) && len(value) > 1:
		boolQuery := bleve.NewBooleanQuery()
		boolQuery.AddMustNot(NewMatchPhrasePrefixQuery(field, value[1:]))
		// This is where things are interesting. BooleanQuery basically generates a true or false that can be used
		// however we must pipe in the search category because the boolean query returns a true/false designation
		boolQuery.AddMust(typeQuery(category))
		return boolQuery, nil
	case strings.HasPrefix(value, regexPrefix) && len(value) > 1:
		q := bleve.NewRegexpQuery(value[1:])
		q.SetField(field)
		return q, nil
	default:
		return NewMatchPhrasePrefixQuery(field, value), nil
	}
}

func newBoolQuery(_ v1.SearchCategory, field string, value string) (query.Query, error) {
	b, err := strconv.ParseBool(value)
	if err != nil {
		return nil, err
	}
	q := bleve.NewBoolFieldQuery(b)
	q.FieldVal = field
	return q, nil
}

func stringToSeverity(s string) (v1.Severity, error) {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "l") {
		return v1.Severity_LOW_SEVERITY, nil
	}
	if strings.HasPrefix(s, "m") {
		return v1.Severity_MEDIUM_SEVERITY, nil
	}
	if strings.HasPrefix(s, "h") {
		return v1.Severity_HIGH_SEVERITY, nil
	}
	if strings.HasPrefix(s, "c") {
		return v1.Severity_CRITICAL_SEVERITY, nil
	}
	return v1.Severity_UNSET_SEVERITY, fmt.Errorf("Could not parse severity '%s'. Valid options are low, medium, high, critical", s)
}

func newExactNumericMatch(field string, f float64) query.Query {
	t := true
	q := bleve.NewNumericRangeInclusiveQuery(&f, &f, &t, &t)
	q.FieldVal = field
	return q
}

func newSeverityQuery(_ v1.SearchCategory, field string, value string) (query.Query, error) {
	sev, err := stringToSeverity(value)
	if err != nil {
		return nil, err
	}
	return newExactNumericMatch(field, float64(sev)), nil
}

func stringToEnforcement(s string) (v1.EnforcementAction, error) {
	s = strings.ToLower(s)
	if strings.Contains(s, "scale") {
		return v1.EnforcementAction_SCALE_TO_ZERO_ENFORCEMENT, nil
	}
	if strings.Contains(s, "node") {
		return v1.EnforcementAction_UNSATISFIABLE_NODE_CONSTRAINT_ENFORCEMENT, nil
	}
	if strings.Contains(s, "none") {
		return v1.EnforcementAction_UNSET_ENFORCEMENT, nil
	}
	return v1.EnforcementAction_UNSET_ENFORCEMENT, fmt.Errorf("Could not parse enforcement '%s'. Valid options are node, and scale", s)
}

func newEnforcementQuery(_ v1.SearchCategory, field string, value string) (query.Query, error) {
	en, err := stringToEnforcement(value)
	if err != nil {
		return nil, err
	}
	return newExactNumericMatch(field, float64(en)), nil
}
