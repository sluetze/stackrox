package index

import (
	"testing"

	"github.com/blevesearch/bleve"
	"github.com/stackrox/rox/central/globalindex"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	fakeID = "ABC"
)

func TestPolicyIndex(t *testing.T) {
	suite.Run(t, new(SecretIndexTestSuite))
}

type SecretIndexTestSuite struct {
	suite.Suite

	bleveIndex bleve.Index

	indexer Indexer
}

func (suite *SecretIndexTestSuite) SetupSuite() {
	tmpIndex, err := globalindex.TempInitializeIndices("")
	suite.Require().NoError(err)

	suite.bleveIndex = tmpIndex
	suite.indexer = New(tmpIndex)

	secret := fixtures.GetSecret()
	suite.NoError(suite.indexer.UpsertSecret(secret))

	secondSecret := fixtures.GetSecret()
	secondSecret.Id = fakeID
	suite.NoError(suite.indexer.UpsertSecret(secondSecret))
}

func (suite *SecretIndexTestSuite) TestSecretSearch() {
	cases := []struct {
		name        string
		q           *v1.Query
		expectedIDs []string
	}{
		{
			name:        "Empty",
			q:           search.EmptyQuery(),
			expectedIDs: []string{fakeID, fixtures.GetSecret().GetId()},
		},
	}

	for _, c := range cases {
		suite.T().Run(c.name, func(t *testing.T) {
			results, err := suite.indexer.Search(c.q)
			require.NoError(t, err)
			resultIDs := make([]string, 0, len(results))
			for _, r := range results {
				resultIDs = append(resultIDs, r.ID)
			}
			assert.ElementsMatch(t, resultIDs, c.expectedIDs)
		})
	}
}

func (suite *SecretIndexTestSuite) TearDownSuite() {
	suite.NoError(suite.bleveIndex.Close())
}
