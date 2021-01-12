package mtls

import (
	"errors"
	"path"
	"path/filepath"
	"runtime"

	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/testutils/envisolator"
)

// LoadTestMTLSCerts loads test TLS certificates into the according environment variables
func LoadTestMTLSCerts(envIsolator *envisolator.EnvIsolator) error {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("Could not read stack trace.")
	}
	dir := filepath.Dir(filename)

	// Certs generated by testdata/generate-certs.sh
	centralCertsDir := filepath.Join(dir, "testdata", "central-certs")
	envIsolator.Setenv(mtls.CAFileEnvName, path.Join(centralCertsDir, "ca.pem"))
	envIsolator.Setenv(mtls.CAKeyFileEnvName, path.Join(centralCertsDir, "ca-key.pem"))
	envIsolator.Setenv(mtls.CertFilePathEnvName, path.Join(centralCertsDir, "leaf-cert.pem"))
	envIsolator.Setenv(mtls.KeyFileEnvName, path.Join(centralCertsDir, "leaf-key.pem"))
	return nil
}
