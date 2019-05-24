package mappings

import (
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/search/blevesearch"
)

// OptionsMap is the map of indexed fields in service account and relationship objects.
var OptionsMap = blevesearch.Walk(v1.SearchCategory_SERVICE_ACCOUNTS, "serviceaccount", (*storage.ServiceAccount)(nil))
