package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	cflog "github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/cmd/deploy/central"
	"github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/version"
	"github.com/stackrox/rox/pkg/zip"
)

func init() {
	// The cfssl library prints logs at Info level when it processes a
	// Certificate Signing Request (CSR) or issues a new certificate.
	// These logs do not help the user understand anything, so here
	// we adjust the log level to exclude them.
	cflog.Level = cflog.LevelWarning
}

var (
	clairifyImage = "clairify:" + version.GetClairifyVersion()
	mainTag       = version.GetMainVersion()
	mainImage     = "main:" + mainTag

	generatedMonitoringPassword = central.CreatePassword()
)

func generateJWTSigningKey(fileMap map[string][]byte) error {
	// Generate the private key that we will use to sign JWTs for API keys.
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("couldn't generate private key: %s", err)
	}
	fileMap["jwt-key.der"] = x509.MarshalPKCS1PrivateKey(privateKey)
	return nil
}

func generateMTLSFiles(fileMap map[string][]byte) (cert, key []byte, err error) {
	// Add MTLS files
	req := csr.CertificateRequest{
		CN:         "StackRox Certificate Authority",
		KeyRequest: csr.NewBasicKeyRequest(),
	}
	cert, _, key, err = initca.New(&req)
	if err != nil {
		err = fmt.Errorf("could not generate keypair: %s", err)
		return
	}
	fileMap["ca.pem"] = cert
	fileMap["ca-key.pem"] = key
	return
}

func generateMonitoringFiles(fileMap map[string][]byte, caCert, caKey []byte) error {
	monitoringCert, monitoringKey, err := mtls.IssueNewCertFromCA(mtls.Subject{ServiceType: v1.ServiceType_MONITORING_DB_SERVICE, Identifier: "Monitoring DB"},
		caCert, caKey)
	if err != nil {
		return err
	}
	fileMap["monitoring-db-cert.pem"] = monitoringCert
	fileMap["monitoring-db-key.pem"] = monitoringKey

	monitoringCert, monitoringKey, err = mtls.IssueNewCertFromCA(mtls.Subject{ServiceType: v1.ServiceType_MONITORING_UI_SERVICE, Identifier: "Monitoring UI"},
		caCert, caKey)
	if err != nil {
		return err
	}

	fileMap["monitoring-ui-cert.pem"] = monitoringCert
	fileMap["monitoring-ui-key.pem"] = monitoringKey

	monitoringCert, monitoringKey, err = mtls.IssueNewCertFromCA(mtls.Subject{ServiceType: v1.ServiceType_MONITORING_CLIENT_SERVICE, Identifier: "Monitoring Client"},
		caCert, caKey)
	if err != nil {
		return err
	}

	fileMap["monitoring-client-cert.pem"] = monitoringCert
	fileMap["monitoring-client-key.pem"] = monitoringKey

	return nil
}

func outputZip(config central.Config) error {
	fmt.Fprint(os.Stderr, "Generating deployment bundle... ")

	wrapper := zip.NewWrapper()

	d, ok := central.Deployers[config.ClusterType]
	if !ok {
		return fmt.Errorf("undefined cluster deployment generator: %s", config.ClusterType)
	}

	config.SecretsByteMap = make(map[string][]byte)
	if err := generateJWTSigningKey(config.SecretsByteMap); err != nil {
		return err
	}

	if features.HtpasswdAuth.Enabled() {
		if config.Environment == nil {
			config.Environment = make(map[string]string)
		}
		config.Environment[features.HtpasswdAuth.EnvVar()] = "true"

		htpasswd, err := central.GenerateHtpasswd(&config)
		if err != nil {
			return err
		}

		config.SecretsByteMap["htpasswd"] = htpasswd
		wrapper.AddFiles(zip.NewFile("password", []byte(config.Password+"\n"), zip.Sensitive))
	}

	cert, key, err := generateMTLSFiles(config.SecretsByteMap)
	if err != nil {
		return err
	}

	if config.K8sConfig != nil && config.K8sConfig.MonitoringType.OnPrem() {
		generateMonitoringFiles(config.SecretsByteMap, cert, key)

		config.SecretsByteMap["monitoring-password"] = []byte(config.K8sConfig.MonitoringPassword)
	}

	config.SecretsBase64Map = make(map[string]string)
	for k, v := range config.SecretsByteMap {
		config.SecretsBase64Map[k] = base64.StdEncoding.EncodeToString(v)
	}

	files, err := d.Render(config)
	if err != nil {
		return fmt.Errorf("could not render files: %s", err)
	}
	wrapper.AddFiles(files...)

	bytes, err := wrapper.Zip()
	if err != nil {
		return fmt.Errorf("error generating zip file: %v", err)
	}
	_, err = os.Stdout.Write(bytes)
	if err != nil {
		return fmt.Errorf("couldn't write zip file: %s", err)
	}

	fmt.Fprintln(os.Stderr, "Done!")
	fmt.Fprintln(os.Stderr)
	cfg.WriteInstructions(os.Stderr)

	return nil
}

func root() *cobra.Command {
	c := &cobra.Command{
		Use:          "root",
		SilenceUsage: true,
	}
	c.PersistentFlags().Var(&featureValue{&cfg.Features}, "flags", "Feature flags to enable")
	c.PersistentFlags().MarkHidden("flags")
	c.AddCommand(interactive())
	c.AddCommand(cmd())
	return c
}

func interactive() *cobra.Command {
	return &cobra.Command{
		Use: "interactive",
		RunE: func(c *cobra.Command, args []string) error {
			c = cmd()
			c.SilenceUsage = true
			return runInteractive(c)
		},
		SilenceUsage: true,
	}
}

func cmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy generates deployment files for StackRox Central",
		Long: `Deploy generates deployment files for StackRox Central.
Output is a zip file printed to stdout.`,
		Run: func(*cobra.Command, []string) {
			printToStderr("Orchestrator is required\n")
		},
	}
	if features.HtpasswdAuth.Enabled() {
		c.PersistentFlags().StringVar(&cfg.Password, "password", "", "administrator password (default: autogenerated)")
	}
	c.AddCommand(k8s())
	c.AddCommand(openshift())
	c.AddCommand(dockerBasedOrchestrator("swarm", "Docker Swarm", v1.ClusterType_SWARM_CLUSTER))
	return c
}

func runInteractive(cmd *cobra.Command) error {
	// Overwrite os.Args because cobra uses them
	os.Args = walkTree(cmd)
	return cmd.Execute()
}

func main() {
	root().Execute()
}
