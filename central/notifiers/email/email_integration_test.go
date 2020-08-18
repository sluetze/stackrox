// +build integration

package email

import (
	"context"
	"os"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	server   = "smtp.mailgun.org"
	user     = "postmaster@sandboxd6576ea8be3c477989eba2c14735d2e6.mailgun.org"
	password = "ec221fbe09156dfef5bd48afb71d277c"

	recipientTestEnv = "EMAIL_RECIPIENT"
)

func skip(t *testing.T) string {
	recipient := os.Getenv(recipientTestEnv)
	if recipient == "" {
		t.Skipf("Skipping email integration test because %v is not defined", recipientTestEnv)
	}
	return recipient
}

func getEmail(t *testing.T) *email {
	recipient := skip(t)

	notifier := &storage.Notifier{
		UiEndpoint: "http://google.com",
		Config: &storage.Notifier_Email{
			Email: &storage.Email{
				Server:     server,
				Sender:     user,
				Username:   recipient,
				Password:   password,
				DisableTLS: true,
			},
		},
	}

	e, err := newEmail(notifier)
	require.NoError(t, err)
	return e
}

func TestEmailAlertNotify(t *testing.T) {
	e := getEmail(t)
	assert.NoError(t, e.AlertNotify(context.Background(), fixtures.GetAlert()))
}

func TestEmailNetworkPolicyYAMLNotify(t *testing.T) {
	e := getEmail(t)

	assert.NoError(t, e.NetworkPolicyYAMLNotify(context.Background(), fixtures.GetYAML(), "test-cluster"))
}

func TestEmailTest(t *testing.T) {
	e := getEmail(t)
	assert.NoError(t, e.Test(context.Background()))
}
