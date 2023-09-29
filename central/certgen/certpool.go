package certgen

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/certgen"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/sync"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
)

var (
	caLifetimeEnv = env.RegisterSetting("CA_LIFETIME", env.WithDefault("2m"))
	// CertLifetimeEnv is the environment variable for the lifetime of the certificates.
	certLifetimeEnv = env.RegisterSetting("CERT_LIFETIME", env.WithDefault("1m"))
	// CertRenewalPercent is the percentage of the certificate lifetime after which the certificate should be renewed.
	certRenewalPercentEnv = env.RegisterSetting("CERT_RENEWAL_PERCENT", env.WithDefault("50"))
	// certReconciliationInterval is the interval at which the certgen reconciler runs.
	certReconciliationIntervalEnv = env.RegisterSetting("CERT_RECONCILIATION_INTERVAL", env.WithDefault("5s"))
)

const (
	centralActiveTlsSecretName = "central-internal-tls"
	centralTLSLabel            = "platform.stackrox.io/central-tls"
)

func init() {
	var err error
	caLifetime, err = time.ParseDuration(caLifetimeEnv.Setting())
	if err != nil {
		panic(fmt.Sprintf("invalid CA lifetime: %v", err))
	}
	certLifetime, err = time.ParseDuration(certLifetimeEnv.Setting())
	if err != nil {
		panic(fmt.Sprintf("invalid cert lifetime: %v", err))
	}
	certRenewalPercent, err = strconv.Atoi(certRenewalPercentEnv.Setting())
	if err != nil {
		panic(fmt.Sprintf("invalid cert renewal percent: %v", err))
	}
	if certRenewalPercent < 0 || certRenewalPercent > 100 {
		panic(fmt.Sprintf("invalid cert renewal percent: %v", certRenewalPercent))
	}
	certReconciliationInterval, err = time.ParseDuration(certReconciliationIntervalEnv.Setting())
	if err != nil {
		panic(fmt.Sprintf("invalid cert reconciliation interval: %v", err))
	}
}

var (
	caLifetime                 time.Duration
	certLifetime               time.Duration
	certReconciliationInterval time.Duration
	certRenewalPercent         int

	centralSubjects = []mtls.Subject{
		mtls.CentralDBSubject,
		mtls.ScannerSubject,
		mtls.ScannerDBSubject,
	}

	securedClusterSubjects = []mtls.Subject{
		mtls.ScannerSubject,
		mtls.ScannerDBSubject,
		mtls.SensorSubject,
		mtls.AdmissionControlSubject,
	}

	log = logging.LoggerForModule()
)

type parsedCaBundle struct {
	caCert tls.Certificate
	cert   tls.Certificate
	secret *v1.Secret
	ca     mtls.CA
}

type parsedServiceBundle struct {
	cert       tls.Certificate
	certPem    []byte
	certKeyPem []byte
	secret     *v1.Secret
	ca         x509.Certificate
}

// TLSConfigurer is an interface for configuring a TLS connection.
type TLSConfigurer interface {
	// Configure configures the TLS connection.
	Configure(config *tls.Config) error
	// Start starts the TLS configurer.
	Start(ctx context.Context)
}

// centralTlsConfigurer is a TLSConfigurer for configuring the Central TLS connection.
type centralTlsConfigurer struct {
	k8s       kubernetes.Interface
	primaryCa tls.Certificate
	cas       []tls.Certificate
	certs     []tls.Certificate
	lock      sync.RWMutex
}

func NewCentralTLSConfigurer(k8s kubernetes.Interface) TLSConfigurer {
	return &centralTlsConfigurer{k8s: k8s}
}

func (c *centralTlsConfigurer) Configure(config *tls.Config) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if len(c.certs) == 0 {
		return fmt.Errorf("no central certs available")
	}
	config.Certificates = append(config.Certificates, c.certs...)
	config.RootCAs = x509.NewCertPool()
	for _, ca := range c.cas {
		config.RootCAs.AddCert(ca.Leaf)
	}
	return nil
}

func (c *centralTlsConfigurer) Start(ctx context.Context) {
	log.Info("starting central tls configurer")
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for ; ; <-ticker.C {
			select {
			case <-ctx.Done():
				log.Infow("stopping central tls configurer")
				return
			default:
				c.reconcile()
			}
		}
	}()
}

func (r *centralTlsConfigurer) reconcile() {

	ctx, cancel := context.WithTimeout(context.Background(), certReconciliationInterval)
	defer cancel()

	now := time.Now()

	caBundles, err := r.reconcileCentralCABundles(ctx, now)
	if err != nil {
		log.Errorf("failed to reconcile central CA bundles: %v", err)
		return
	}

	sortCaBundles(caBundles, now)

	caBundles, err = r.createCentralBundleIfNeeded(ctx, caBundles, now)
	if err != nil {
		log.Errorf("failed to create central CA bundle: %v", err)
		return
	}

	// Still need to sort it after (maybe) adding an item. ugly
	sortCaBundles(caBundles, now)

	// At this point it is assured that the caBundles is not empty
	// And the first CA is the one we want to use
	primaryCABundle := caBundles[0]

	if err := r.reconcileServiceCerts(ctx, primaryCABundle.ca, centralSubjects, now); err != nil {
		log.Errorf("failed to reconcile service certs: %v", err)
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.primaryCa = primaryCABundle.caCert
	r.cas = []tls.Certificate{}
	r.certs = []tls.Certificate{}

	for _, secret := range caBundles {
		r.cas = append(r.cas, secret.caCert)
		r.certs = append(r.certs, secret.cert)
	}

}

func (r *centralTlsConfigurer) reconcileCentralCABundles(ctx context.Context, now time.Time) ([]parsedCaBundle, error) {
	// List all the central tls secrets
	listOptions := metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", centralTLSLabel)}
	secretList, err := r.k8s.CoreV1().Secrets(env.Namespace.Setting()).List(ctx, listOptions)
	if err != nil {
		log.Errorf("failed to list central tls secrets: %v", err)
		return nil, err
	}

	var validSecrets []parsedCaBundle
	for _, secret := range secretList.Items {
		// Reconcile the secret.
		parsed, skip, err := r.reconcileCentralTLSSecret(ctx, &secret, now)
		if err != nil {
			log.Errorf("failed to reconcile central tls secret %s: %v", secret.Name, err)
			return nil, err
		}
		if skip {
			continue
		}
		validSecrets = append(validSecrets, parsed)
	}
	return validSecrets, nil
}

func (r *centralTlsConfigurer) createCentralBundleIfNeeded(ctx context.Context, caBundles []parsedCaBundle, now time.Time) ([]parsedCaBundle, error) {

	if len(caBundles) == 0 {
		log.Infof("no valid central CA found. reissuing")
	} else if hasReachedPercentOfLifetime(caBundles[0].caCert, certRenewalPercent, now) {
		log.Infof("current central CA %s is expiring: %v", caBundles[0].secret.Name, getCertExpirationDescription(caBundles[0].caCert, now))
		for i, caBundle := range caBundles {
			log.Infof("central CA %d/%d notAfter: %v", i+1, len(caBundles), caBundle.caCert.Leaf.NotAfter)
		}
	} else {
		return caBundles, nil
	}

	newSecret, err := generateNewCentralTLSSecret(now)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate new central tls secret")
	}

	createdSecret, err := r.k8s.CoreV1().Secrets(env.Namespace.Setting()).Create(ctx, newSecret, metav1.CreateOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new central tls secret")
	}

	parsedNewSecret, err := parseCentralBundle(createdSecret)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse new central tls secret")
	}

	caBundles = append(caBundles, parsedNewSecret)

	return caBundles, nil
}

// reconcileCentralTLSSecret will reconcile the given secret.
// It will delete the secret if the secret or the CA is not valid anymore
// It will re-issue the certs if they are about to expire or invalid against the CA
// It will return the parsed bundle, whether the secret should be skipped, and an error if any
func (r *centralTlsConfigurer) reconcileCentralTLSSecret(ctx context.Context, secret *v1.Secret, now time.Time) (parsedCaBundle, bool, error) {
	secretName := secret.Name

	// Ignore secrets that are being deleted
	if secret.DeletionTimestamp != nil {
		log.Infof("ignoring deleted central tls secret %s", secretName)
		return parsedCaBundle{}, true, nil
	}

	// Parse the secret into a central bundle
	parsed, err := parseCentralBundle(secret)
	if err != nil {
		log.Errorf("failed to parse central tls secret %s: %v. Deleting", secretName, err)
		if err := r.k8s.CoreV1().Secrets(env.Namespace.Setting()).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil && !k8sErrors.IsNotFound(err) {
			return parsedCaBundle{}, false, errors.Wrapf(err, "failed to delete invalid central tls secret")
		}
		return parsedCaBundle{}, true, nil
	}

	caNotAfter := parsed.caCert.Leaf.NotAfter
	certNotAfter := parsed.cert.Leaf.NotAfter

	// Delete CAs that are expired
	if hasReachedPercentOfLifetime(parsed.caCert, certRenewalPercent, now) {
		log.Infof("central tls secret %s CA is expired. deleting", secretName)
		if err := r.k8s.CoreV1().Secrets(env.Namespace.Setting()).Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil && !k8sErrors.IsNotFound(err) {
			return parsedCaBundle{}, false, errors.Wrapf(err, "failed to delete invalid central tls secret")
		}
		return parsedCaBundle{}, true, nil
	}

	var shouldReissue = false

	// If the cert is expiring
	if hasReachedPercentOfLifetime(parsed.cert, certRenewalPercent, now) {
		log.Infof("reissuing central tls secret %s: %v", secretName, err)
		// reissue only if the cert expiration is before the CA expiration
		shouldReissue = certNotAfter.Before(caNotAfter)
	}

	// If the cert is invalid against the CA, reissue
	if !shouldReissue {
		if err := verifyCertAgainstCaCert(parsed.caCert.Leaf, parsed.cert); err != nil {
			log.Infof("reissuing central tls secret %s: %v", secretName, err)
			shouldReissue = true
		}
	}

	if shouldReissue {
		newParsed, err := r.reissueCentralCerts(ctx, parsed, now)
		if err != nil {
			return parsedCaBundle{}, false, errors.Wrapf(err, "failed to reissue central certs")
		}
		return newParsed, false, nil
	}

	return parsed, false, nil

}

// reissueCentralCerts will re-create the service certs for central.
// It will return the modified parsedCaBundle and an error if any
func (t *centralTlsConfigurer) reissueCentralCerts(ctx context.Context, parsed parsedCaBundle, now time.Time) (parsedCaBundle, error) {

	// Generate the central cert
	newCentralCert, err := generateServiceCert(now, parsed.ca, mtls.CentralSubject)
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to generate central cert")
	}

	newCertPEM := newCentralCert.CertPEM
	newKeyPEM := newCentralCert.KeyPEM

	newCert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to parse new central tls keypair")
	}

	newCert.Leaf, err = x509.ParseCertificate(newCert.Certificate[0])
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to parse new central tls keypair cert")
	}

	log.Infof("Generated new central cert")
	log.Infof("NotBefore: %s", newCert.Leaf.NotBefore)
	log.Infof("NotAfter: %s", newCert.Leaf.NotAfter)

	// Updating the secret with the new cert
	newSecret := parsed.secret.DeepCopy()
	newSecret.Data[mtls.ServiceCertFileName] = newCertPEM
	newSecret.Data[mtls.ServiceKeyFileName] = newKeyPEM
	updatedSecret, err := t.k8s.CoreV1().Secrets(env.Namespace.Setting()).Update(ctx, newSecret, metav1.UpdateOptions{})
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to update central tls secret")
	}

	parsed.cert = newCert
	parsed.secret = updatedSecret

	return parsed, nil
}

// reconcileServiceCerts will reconcile the service certs for the given subjects.
func (t *centralTlsConfigurer) reconcileServiceCerts(ctx context.Context, ca mtls.CA, subjects []mtls.Subject, now time.Time) error {
	for _, subject := range subjects {
		if err := t.reconcileServiceCert(ctx, ca, subject, now); err != nil {
			return errors.Wrapf(err, "failed to reconcile service cert for %s", subject.Identifier)
		}
	}
	return nil
}

// reconcileServiceCert will reconcile the service cert for the given subject.
func (t *centralTlsConfigurer) reconcileServiceCert(ctx context.Context, ca mtls.CA, subject mtls.Subject, now time.Time) error {
	secretName := getTLSSecretNameForSubject(subject)
	existingSecret, err := t.k8s.CoreV1().Secrets(env.Namespace.Setting()).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return errors.Wrapf(err, "failed to get existing service cert for %s", subject.Identifier)
	}

	if err != nil {
		generated, err := generateServiceCertSecret(ca, subject, now)
		if err != nil {
			return err
		}
		if _, err := t.k8s.CoreV1().Secrets(env.Namespace.Setting()).Create(ctx, generated, metav1.CreateOptions{}); err != nil {
			return errors.Wrap(err, "failed to create service cert")
		}
		return nil
	}

	if _, err := t.reconcileExistingServiceCert(ctx, existingSecret, ca, subject, now); err != nil {
		return errors.Wrap(err, "failed to reconcile existing service cert")
	}

	return nil
}

func (t *centralTlsConfigurer) reconcileExistingServiceCert(ctx context.Context, existingSecret *v1.Secret, ca mtls.CA, subject mtls.Subject, now time.Time) (*v1.Secret, error) {

	secretName := existingSecret.Name

	if existingSecret.DeletionTimestamp != nil {
		log.Infof("ignoring deleted service cert %s", secretName)
		return existingSecret, nil
	}

	var shouldRecreate bool

	// parse the secret
	serviceBundle, err := parseServiceBundle(existingSecret)
	if err != nil {
		log.Errorf("failed to parse service cert %s: %v. Deleting", secretName, err)
		shouldRecreate = true
	}

	// check if the cert is signed by the desired CA
	if !shouldRecreate {
		if err := verifyCertAgainstCaCert(ca.Certificate(), serviceBundle.cert); err != nil {
			log.Infof("reissuing service cert %s because of CA mismatch: %v", secretName, err)
			shouldRecreate = true
		}
	}

	// check if the cert is expiring
	if !shouldRecreate {
		if hasReachedPercentOfLifetime(serviceBundle.cert, certRenewalPercent, now) {
			log.Infof("reissuing service cert secret %s: %s", secretName, getCertExpirationDescription(serviceBundle.cert, now))
			shouldRecreate = true
		}
	}

	if !shouldRecreate {
		return existingSecret, nil
	}

	// update the secret
	generated, err := generateServiceCertSecret(ca, subject, now)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate service cert")
	}
	existingSecret.Data = generated.Data
	updatedSecret, err := t.k8s.CoreV1().Secrets(env.Namespace.Setting()).Update(ctx, existingSecret, metav1.UpdateOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to update service cert")
	}

	return updatedSecret, nil

}

func generateNewCentralTLSSecret(now time.Time) (*v1.Secret, error) {

	// Generate the CA
	ca, err := certgen.GenerateCA(func(request *csr.CertificateRequest) {
		if request.CA == nil {
			request.CA = &csr.CAConfig{}
		}
		request.CA.Expiry = caLifetime.String()
		request.CA.Backdate = time.Minute.String()
	})
	if err != nil {
		return nil, errors.Wrap(err, "creating new CA")
	}

	log.Info("Central CA generated")
	log.Infof("NotBefore: %s", ca.Certificate().NotBefore)
	log.Infof("NotAfter: %s", ca.Certificate().NotAfter)

	certNotAfter := now.Add(certLifetime)
	if certNotAfter.After(ca.Certificate().NotAfter) {
		certNotAfter = ca.Certificate().NotAfter.UTC()
	}

	// Generate the central cert
	centralCert, err := generateServiceCert(now, ca, mtls.CentralSubject)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate central cert")
	}

	hash, err := computeHashFor(ca)
	name := fmt.Sprintf("%s-%s", centralActiveTlsSecretName, hash)

	s := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: env.Namespace.Setting(),
			Labels: map[string]string{
				centralTLSLabel: "true",
			},
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			mtls.CACertFileName:      ca.CertPEM(),
			mtls.CAKeyFileName:       ca.KeyPEM(),
			mtls.ServiceCertFileName: centralCert.CertPEM,
			mtls.ServiceKeyFileName:  centralCert.KeyPEM,
		},
	}

	return &s, nil
}

func generateServiceCertSecret(ca mtls.CA, subject mtls.Subject, now time.Time) (*v1.Secret, error) {
	cert, err := generateServiceCert(now, ca, subject)
	if err != nil {
		return nil, errors.Wrapf(err, "could not generate cert for %v", subject.Identifier)
	}
	secretName := getTLSSecretNameForSubject(subject)
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: env.Namespace.Setting(),
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			mtls.CACertFileName:      ca.CertPEM(),
			mtls.ServiceCertFileName: cert.CertPEM,
			mtls.ServiceKeyFileName:  cert.KeyPEM,
		},
	}
	return secret, nil
}

func generateServiceCert(now time.Time, ca mtls.CA, subject mtls.Subject) (*mtls.IssuedCert, error) {
	notAfter := now.Add(certLifetime)
	if notAfter.After(ca.Certificate().NotAfter) {
		notAfter = ca.Certificate().NotAfter.UTC()
	}
	cert, err := ca.IssueCertForSubject(subject,
		mtls.WithNotAfter(notAfter),
		mtls.WithNotBefore(now.Add(-time.Minute)),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "could not issue cert for %s", subject.Identifier)
	}
	return cert, nil
}

func verifyCertAgainstCaCert(caCert *x509.Certificate, cert tls.Certificate) error {
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	_, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots: caCertPool,
	})
	return err
}

func hasReachedPercentOfLifetime(cert tls.Certificate, percent int, now time.Time) bool {
	return getPercentOfLifetimeReached(cert, now) > float64(percent)
}

func getPercentOfLifetimeReached(cert tls.Certificate, now time.Time) float64 {
	return 100 - getPercentOfLifetimeRemaining(cert, now)
}

func getPercentOfLifetimeRemaining(cert tls.Certificate, now time.Time) float64 {
	return (float64(getCertTotalLifetimeDuration(cert)) / float64(getCertRemainingDuration(cert, now))) * 100
}

func getCertTotalLifetimeDuration(cert tls.Certificate) time.Duration {
	return cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
}

func getCertRemainingDuration(cert tls.Certificate, now time.Time) time.Duration {
	return cert.Leaf.NotAfter.Sub(now)
}

func getCertExpirationDescription(cert tls.Certificate, now time.Time) string {
	hasExpired := cert.Leaf.NotAfter.Before(now) || cert.Leaf.NotAfter.Equal(now)
	d := &strings.Builder{}

	if hasExpired {
		d.WriteString("has expired ")
	} else {
		d.WriteString("expires in ")
	}

	d.WriteString(getCertRemainingDuration(cert, now).Truncate(time.Second).String())

	if hasExpired {
		d.WriteString(" ago")
	} else {
		d.WriteString(fmt.Sprintf(" (%.2f%% remaining of %s)",
			getPercentOfLifetimeRemaining(cert, now),
			getCertTotalLifetimeDuration(cert).String()),
		)
	}

	return d.String()
}

func getTLSSecretNameForSubject(subject mtls.Subject) string {
	switch subject.ServiceType {
	case mtls.CentralDBSubject.ServiceType:
		return "central-db-internal-tls"
	case mtls.ScannerSubject.ServiceType:
		return "scanner-internal-tls"
	case mtls.ScannerDBSubject.ServiceType:
		return "scanner-db-internal-tls"
	case mtls.SensorSubject.ServiceType:
		return "sensor-internal-tls"
	case mtls.AdmissionControlSubject.ServiceType:
		return "admission-control-internal-tls"
	default:
		panic(fmt.Sprintf("unknown service type %s", subject.ServiceType))
	}
}

func parseServiceBundle(secret *v1.Secret) (parsedServiceBundle, error) {
	// Parse CA
	caCertPemBytes, ok := secret.Data[mtls.CACertFileName]
	if !ok {
		return parsedServiceBundle{}, fmt.Errorf("CA cert not found")
	}
	caCertPem, rest := pem.Decode(caCertPemBytes)
	if caCertPem == nil {
		return parsedServiceBundle{}, fmt.Errorf("failed to decode CA cert")
	}
	if len(rest) > 0 {
		return parsedServiceBundle{}, fmt.Errorf("trailing data after CA cert")
	}
	caCert, err := x509.ParseCertificate(caCertPem.Bytes)
	if err != nil {
		return parsedServiceBundle{}, errors.Wrap(err, "failed to parse CA cert")
	}

	// Parse key
	keyPemBytes, ok := secret.Data[mtls.ServiceKeyFileName]
	if !ok {
		return parsedServiceBundle{}, fmt.Errorf("service key not found")
	}

	// Parse cert
	certPemBytes, ok := secret.Data[mtls.ServiceCertFileName]
	if !ok {
		return parsedServiceBundle{}, fmt.Errorf("service cert not found")
	}
	cert, err := tls.X509KeyPair(certPemBytes, keyPemBytes)
	if err != nil {
		return parsedServiceBundle{}, errors.Wrap(err, "failed to parse service keypair")
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return parsedServiceBundle{}, errors.Wrap(err, "failed to parse service cert")
	}

	// verify that the cert is signed by the CA
	if err := verifyCertAgainstCaCert(caCert, cert); err != nil {
		return parsedServiceBundle{}, errors.Wrap(err, "service cert is not signed by CA")
	}
	return parsedServiceBundle{
		cert:       cert,
		certPem:    certPemBytes,
		certKeyPem: keyPemBytes,
		secret:     secret,
		ca:         *caCert,
	}, nil
}

func parseCentralBundle(secret *v1.Secret) (parsedCaBundle, error) {
	if secret.Data == nil {
		return parsedCaBundle{}, fmt.Errorf("secret data is nil")
	}
	caCertBytes, ok := secret.Data[mtls.CACertFileName]
	if !ok {
		return parsedCaBundle{}, fmt.Errorf("central CA cert not found")
	}
	caKeyBytes, ok := secret.Data[mtls.CAKeyFileName]
	if !ok {
		return parsedCaBundle{}, fmt.Errorf("central CA key not found")
	}
	centralCertBytes, ok := secret.Data[mtls.ServiceCertFileName]
	if !ok {
		return parsedCaBundle{}, fmt.Errorf("central cert not found")
	}
	centralKeyBytes, ok := secret.Data[mtls.ServiceKeyFileName]
	if !ok {
		return parsedCaBundle{}, fmt.Errorf("central key not found")
	}
	caCert, err := tls.X509KeyPair(caCertBytes, caKeyBytes)
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to parse central CA keypair")
	}
	caCert.Leaf, err = x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to parse central CA cert")
	}
	centralCert, err := tls.X509KeyPair(centralCertBytes, centralKeyBytes)
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to parse central cert keypair")
	}
	centralCert.Leaf, err = x509.ParseCertificate(centralCert.Certificate[0])
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to parse central cert cert")
	}
	ca, err := mtls.LoadCAForSigning(caCertBytes, caKeyBytes)
	if err != nil {
		return parsedCaBundle{}, errors.Wrap(err, "failed to load CA for signing")
	}
	return parsedCaBundle{
		ca:     ca,
		caCert: caCert,
		cert:   centralCert,
		secret: secret,
	}, nil
}

func computeHashFor(ca mtls.CA) (string, error) {
	h := fnv.New32a()
	if _, err := h.Write(ca.CertPEM()); err != nil {
		return "", errors.Wrap(err, "failed to write cert hash")
	}
	if _, err := h.Write(ca.KeyPEM()); err != nil {
		return "", errors.Wrap(err, "failed to write key hash")
	}
	hash := rand.SafeEncodeString(fmt.Sprint(h.Sum32()))
	return hash, nil
}

func sortCaBundles(parsed []parsedCaBundle, now time.Time) {
	// we want the Ca cert that has the longest lifetime to be first
	// if equal, sort by secret name
	sort.Slice(parsed, func(i, j int) bool {
		left := parsed[i]
		right := parsed[j]
		leftCaExpiring := hasReachedPercentOfLifetime(left.caCert, certRenewalPercent, now)
		rightCaExpiring := hasReachedPercentOfLifetime(right.caCert, certRenewalPercent, now)
		if leftCaExpiring != rightCaExpiring {
			return !leftCaExpiring
		}
		leftNotAfter := left.caCert.Leaf.NotAfter
		rightNotAfter := right.caCert.Leaf.NotAfter
		if leftNotAfter.Equal(rightNotAfter) {
			return left.secret.CreationTimestamp.After(right.secret.CreationTimestamp.Time)
		}
		return leftNotAfter.After(rightNotAfter)
	})
}
