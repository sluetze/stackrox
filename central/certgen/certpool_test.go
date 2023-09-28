package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSort(t *testing.T) {
	now := time.Now()
	p1 := generateParsed("test-1", now.Add(time.Hour))
	p2 := generateParsed("test-2", now.Add(time.Hour*2))
	p3 := generateParsed("test-3", now.Add(time.Hour*3))
	p4 := generateParsed("test-4", now.Add(time.Hour*3))

	parsedSecrets := []parsedCaBundle{p2, p4, p3, p1}
	sortCaBundles(parsedSecrets)

	assert.Equal(t, p3, parsedSecrets[0])
	assert.Equal(t, p4, parsedSecrets[1])
	assert.Equal(t, p2, parsedSecrets[2])
	assert.Equal(t, p1, parsedSecrets[3])
}

func TestCAExpiring(t *testing.T) {
	now := time.Now()
	hourAgo := now.Add(-time.Hour)
	inTwenty := now.Add(time.Minute * 19)
	// Total of 80 minutes of lifetime
	// 75% of 80 = 60 minutes
	ca := generateCa(hourAgo, inTwenty)
	assert.True(t, assertNotExpiring(ca))
}

func TestCANotExpiring(t *testing.T) {
	now := time.Now()
	hourAgo := now.Add(-time.Hour)
	inAnHour := now.Add(time.Hour)
	ca := generateCa(hourAgo, inAnHour)
	assert.True(t, assertNotExpiring(ca))
}

func generateParsed(secretName string, expiry time.Time) parsedCaBundle {
	ca := generateCa(time.Now(), expiry)
	leaf := generateLeaf(ca, expiry)
	return newParsed(secretName, ca, leaf)
}

func newParsed(secretName string, ca tls.Certificate, cert tls.Certificate) parsedCaBundle {
	caKeyDer, err := x509.MarshalPKCS8PrivateKey(ca.PrivateKey)
	if err != nil {
		panic(err)
	}
	certKeyDer, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		panic(err)
	}
	caKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: caKeyDer,
	})
	certKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: certKeyDer,
	})
	return parsedCaBundle{
		caCert:     ca,
		cert:       cert,
		certKeyPem: certKeyPem,
		caKeyPem:   caKeyPem,
		secret: &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: "test",
			},
			Data: map[string][]byte{
				mtls.CAKeyFileName:       caKeyPem,
				mtls.CACertFileName:      ca.Certificate[0],
				mtls.ServiceCertFileName: cert.Certificate[0],
				mtls.ServiceKeyFileName:  certKeyPem,
			},
		},
	}
}

func generateCa(notBefore time.Time, expiry time.Time) tls.Certificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Red Hat"},
		},
		NotBefore:             notBefore,
		NotAfter:              expiry,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPriv.PublicKey, caPriv)
	if err != nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{caBytes},
		PrivateKey:  caPriv,
		Leaf:        caCert,
	}

}

func generateLeaf(ca tls.Certificate, expiry time.Time) tls.Certificate {
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Red Hat"},
		},
		NotBefore:             now,
		NotAfter:              expiry,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leaf, ca.Leaf, &leafPriv.PublicKey, ca.PrivateKey)
	if err != nil {
		panic(err)
	}
	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{leafBytes},
		PrivateKey:  leafPriv,
		Leaf:        leafCert,
	}
}
