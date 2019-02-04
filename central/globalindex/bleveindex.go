package globalindex

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/analysis/analyzer/custom"
	"github.com/blevesearch/bleve/analysis/token/lowercase"
	"github.com/blevesearch/bleve/analysis/tokenizer/whitespace"
	"github.com/blevesearch/bleve/index/scorch"
	"github.com/blevesearch/bleve/mapping"
	alertMapping "github.com/stackrox/rox/central/alert/index/mappings"
	clusterMapping "github.com/stackrox/rox/central/cluster/index/mappings"
	complianceMapping "github.com/stackrox/rox/central/compliance/search"
	"github.com/stackrox/rox/central/compliance/standards/index"
	deploymentMapping "github.com/stackrox/rox/central/deployment/index/mappings"
	imageMapping "github.com/stackrox/rox/central/image/index/mappings"
	namespaceMapping "github.com/stackrox/rox/central/namespace/index/mappings"
	nodeMapping "github.com/stackrox/rox/central/node/index/mappings"
	policyMapping "github.com/stackrox/rox/central/policy/index/mappings"
	processIndicatorMapping "github.com/stackrox/rox/central/processindicator/index/mappings"
	secretOptions "github.com/stackrox/rox/central/secret/search/options"
	"github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/blevesearch"
)

var (
	// EntityOptionsMap is a mapping from search categories to the options map for that category.
	// search document maps are also built off this map
	EntityOptionsMap = map[v1.SearchCategory]search.OptionsMap{
		v1.SearchCategory_ALERTS:              alertMapping.OptionsMap,
		v1.SearchCategory_DEPLOYMENTS:         deploymentMapping.OptionsMap,
		v1.SearchCategory_IMAGES:              imageMapping.OptionsMap,
		v1.SearchCategory_POLICIES:            policyMapping.OptionsMap,
		v1.SearchCategory_SECRETS:             secretOptions.Map,
		v1.SearchCategory_PROCESS_INDICATORS:  processIndicatorMapping.OptionsMap,
		v1.SearchCategory_COMPLIANCE_STANDARD: index.StandardOptions,
		v1.SearchCategory_COMPLIANCE_CONTROL:  index.ControlOptions,
		v1.SearchCategory_CLUSTERS:            clusterMapping.OptionsMap,
		v1.SearchCategory_NAMESPACES:          namespaceMapping.OptionsMap,
		v1.SearchCategory_NODES:               nodeMapping.OptionsMap,
	}

	// SearchOptionsMap includes options maps that are not required for document mapping
	SearchOptionsMap = func() map[v1.SearchCategory]search.OptionsMap {
		var searchMap = map[v1.SearchCategory]search.OptionsMap{
			v1.SearchCategory_COMPLIANCE: complianceMapping.OptionsMap,
		}
		for k, v := range EntityOptionsMap {
			searchMap[k] = v
		}
		return searchMap
	}

	logger = logging.LoggerForModule()
)

// TempInitializeIndices initializes the index under the tmp system folder in the specified path.
func TempInitializeIndices(mossPath string) (bleve.Index, error) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		return nil, err
	}
	return initializeIndices(filepath.Join(tmpDir, mossPath))
}

// MemOnlyIndex returns a temporary mem-only index.
func MemOnlyIndex() (bleve.Index, error) {
	return bleve.NewMemOnly(getIndexMapping())
}

// InitializeIndices initializes the index in the specified path.
func InitializeIndices(mossPath string) (bleve.Index, error) {
	globalIndex, err := initializeIndices(mossPath)
	if err != nil {
		return nil, err
	}
	go startMonitoring(globalIndex, mossPath)
	return globalIndex, nil
}

func initializeIndices(mossPath string) (bleve.Index, error) {
	indexMapping := getIndexMapping()

	kvconfig := map[string]interface{}{
		// This sounds scary. It's not. It just means that the persistence to disk is not guaranteed
		// which is fine for us because we replay on Central restart
		"unsafe_batch": true,
	}

	// Bleve requires that the directory we provide is already empty.
	err := os.RemoveAll(mossPath)
	if err != nil {
		logger.Warnf("Could not clean up search index path %s: %v", mossPath, err)
	}
	globalIndex, err := bleve.NewUsing(mossPath, indexMapping, scorch.Name, scorch.Name, kvconfig)
	if err != nil {
		return nil, err
	}

	return globalIndex, nil
}

func getIndexMapping() mapping.IndexMapping {
	indexMapping := bleve.NewIndexMapping()
	indexMapping.AddCustomAnalyzer("single_term", singleTermAnalyzer())
	indexMapping.DefaultAnalyzer = "single_term" // Default to our analyzer

	indexMapping.IndexDynamic = false
	indexMapping.StoreDynamic = false
	indexMapping.TypeField = "Type"

	for category, optMap := range EntityOptionsMap {
		indexMapping.AddDocumentMapping(category.String(), blevesearch.DocumentMappingFromOptionsMap(optMap.Original()))
	}

	disabledSection := bleve.NewDocumentDisabledMapping()
	indexMapping.AddDocumentMapping("_all", disabledSection)

	return indexMapping
}

// This is the custom analyzer definition
func singleTermAnalyzer() map[string]interface{} {
	return map[string]interface{}{
		"type":         custom.Name,
		"char_filters": []string{},
		"tokenizer":    whitespace.Name,
		// Ignore case sensitivity
		"token_filters": []string{
			lowercase.Name,
		},
	}
}
