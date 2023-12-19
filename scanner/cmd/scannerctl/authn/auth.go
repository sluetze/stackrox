package authn

import (
	"errors"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
)

const BasicAuthSetting = "ROX_SCANNERCTL_BASIC_AUTH"

func ParseBasic(auth string) (authn.Authenticator, error) {
	if auth == "" {
		auth = os.Getenv(BasicAuthSetting)
	}
	if auth == "" {
		log.Println("auth unspecified: using anonymous auth")
		return authn.Anonymous, nil
	}

	u, p, ok := strings.Cut(auth, ":")
	if !ok {
		return nil, errors.New("invalid basic auth: expecting the username and the " +
			"password with a colon (aladdin:opensesame)")
	}

	return &authn.Basic{
		Username: u,
		Password: p,
	}, nil
}
