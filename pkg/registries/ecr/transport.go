package ecr

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	awsECR "github.com/aws/aws-sdk-go/service/ecr"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/registries/docker"
	"github.com/stackrox/rox/pkg/sync"
)

type awsTransport struct {
	registry.Transport
	config    *docker.Config
	client    *awsECR.ECR
	expiresAt *time.Time
	mutex     sync.Mutex
}

func newAWSTransport(config *docker.Config, client *awsECR.ECR) *awsTransport {
	return &awsTransport{config: config, client: client}
}

func (t *awsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if t.expiresAt == nil || t.expiresAt.After(time.Now()) {
		err := t.refreshNoLock()
		if err != nil {
			return nil, err
		}
	}
	resp, err := t.Transport.RoundTrip(req)
	return resp, err
}

func (t *awsTransport) refreshNoLock() error {
	authToken, err := t.client.GetAuthorizationToken(&awsECR.GetAuthorizationTokenInput{})
	if err != nil {
		return errors.Wrap(err, "failed to get authorization token")
	}
	if len(authToken.AuthorizationData) == 0 {
		return errors.New("received empty authorization data in token")
	}
	authData := authToken.AuthorizationData[0]
	decoded, err := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	if err != nil {
		return errors.Wrap(err, "failed to decode authorization token")
	}
	basicAuth := string(decoded)
	colon := strings.Index(basicAuth, ":")
	if colon == -1 {
		return errors.New("malformed basic auth response from AWS")
	}
	t.config.Username = basicAuth[:colon]
	t.config.Password = basicAuth[colon+1:]
	t.expiresAt = authData.ExpiresAt
	t.Transport = t.config.GetTransport()
	return nil
}
