package requestinfo

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/cryptoutils"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/monoclock"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	requestInfoMDKey    = `rox-requestinfo`
	requestInfoSigMDKey = `rox-requestinfo-sig`

	maxTimeDelta = 2 * time.Second
)

var (
	log = logging.LoggerForModule()
)

type requestInfoKey struct{}

// CertInfo is the relevant (for us) fraction of a X.509 certificate that can safely be serialized.
type CertInfo struct {
	Subject             pkix.Name
	NotBefore, NotAfter time.Time
	EmailAddresses      []string
	SerialNumber        *big.Int
	CertFingerprint     string
}

// HTTPRequest provides a gob encodeable way of passing HTTP Request parameters
type HTTPRequest struct {
	Method  string
	URL     *url.URL
	Headers http.Header
}

// RequestInfo provides a unified view of a GRPC request, regardless of whether it came through the HTTP/1.1 gateway
// or directly via GRPC.
// When forwarding requests in the HTTP/1.1 gateway, there are two independent mechanisms to defend against spoofing:
// - Only requests originating from a local loopback address are permitted to carry a RequestInfo in their metadata.
// - RequestInfos are timestamped, and expire after 200ms. The timestamp is derived from a monotonic clock reading;
//   to prevent attackers from fabricating a RequestInfo with timestamp (in case a monotonic clock reading should ever
//   leak), the entire RequestInfo (with timestamp) is signed with a cryptographic signature.
type RequestInfo struct {
	// Hostname is the hostname specified in a request, as intended by the client. This is derived from the
	// `X-Forwarded-Host` (if present) or the `Hostname` header for a HTTP/1.1 request, and from the TLS ServerName
	// otherwise.
	Hostname string
	// ClientUsedTLS indicates whether the client used TLS (i.e., "https") to connect. This is populated from
	// the `X-Forwarded-Proto` header (if present), or the TLS connection state.
	ClientUsedTLS bool
	// VerifiedSubjectChains are the subjects of the verified certificate chains presented by the client.
	VerifiedChains [][]CertInfo
	// Metadata is the request metadata. For *pure* HTTP/1.1 requests, these are the actual HTTP headers. Otherwise,
	// these are only the headers that make it to the GRPC handler.
	Metadata metadata.MD
	// HTTPRequest is a slimmed down version of *http.Request that will only be populated if the request came through the gateway
	HTTPRequest *HTTPRequest
}

type serializedRequestInfo struct {
	RequestInfo
	RequestMonotime time.Duration
}

// ExtractCertInfo gets the cert info from a cert.
func ExtractCertInfo(fullCert *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:         fullCert.Subject,
		NotBefore:       fullCert.NotBefore,
		NotAfter:        fullCert.NotAfter,
		SerialNumber:    fullCert.SerialNumber,
		EmailAddresses:  fullCert.EmailAddresses,
		CertFingerprint: cryptoutils.CertFingerprint(fullCert),
	}
}

func extractCertInfoChains(fullCertChains [][]*x509.Certificate) [][]CertInfo {
	result := make([][]CertInfo, 0, len(fullCertChains))
	for _, chain := range fullCertChains {
		subjectChain := make([]CertInfo, 0, len(chain))
		for _, cert := range chain {
			subjectChain = append(subjectChain, ExtractCertInfo(cert))
		}
		result = append(result, subjectChain)
	}
	return result
}

// Handler takes care of populating the context with a RequestInfo, as well as handling the
// serialization/deserialization for the HTTP/1.1 gateway.
type Handler struct {
	signer cryptoutils.Signer
	clock  monoclock.MonoClock
}

// NewRequestInfoHandler creates a new request info handler using the given signer for signing requestinfo transmitted
// as GRPC metadata.
func NewRequestInfoHandler(signer cryptoutils.Signer) *Handler {
	return &Handler{
		signer: signer,
		clock:  monoclock.New(),
	}
}

// NewDefaultRequestInfoHandler creates a new request info handler using a default signer.
func NewDefaultRequestInfoHandler() *Handler {
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Panic("Could not generate an ED25519 private key!")
	}
	return NewRequestInfoHandler(cryptoutils.NewED25519Signer(pk))
}

func slimHTTPRequest(req *http.Request) *HTTPRequest {
	return &HTTPRequest{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Header,
	}
}

// AnnotateMD builds a RequestInfo for a request coming in through the HTTP/1.1 gateway, and returns it in serialized
// form as GRPC metadata.
func (h *Handler) AnnotateMD(ctx context.Context, req *http.Request) metadata.MD {
	tlsState := req.TLS

	var ri serializedRequestInfo

	ri.HTTPRequest = slimHTTPRequest(req)

	// X-Forwarded-Host takes precedence in case we are behind a proxy. `Hostname` should match what the client sees.
	if fwdHost := req.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		ri.Hostname = fwdHost
	} else if tlsState != nil {
		ri.Hostname = tlsState.ServerName
	}

	if fwdProto := req.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		ri.ClientUsedTLS = fwdProto != "http"
	} else {
		ri.ClientUsedTLS = tlsState != nil
	}

	if tlsState != nil {
		ri.VerifiedChains = extractCertInfoChains(tlsState.VerifiedChains)
	}

	// Set timestamp
	ri.RequestMonotime = h.clock.SinceEpoch()

	// Encode to GOB and sign.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(ri); err != nil {
		log.Errorf("UNEXPECTED: failed to encode request info to GOB: %v", err)
		return nil
	}
	encodedRI := buf.Bytes()
	sig, err := h.signer.Sign(encodedRI, rand.Reader)
	if err != nil {
		log.Errorf("UNEXPECTED: failed to sign request info GOB: %v", err)
		return nil
	}

	return metadata.MD{
		requestInfoMDKey:    []string{base64.URLEncoding.EncodeToString(encodedRI)},
		requestInfoSigMDKey: []string{base64.URLEncoding.EncodeToString(sig)},
	}
}

func tlsStateFromContext(ctx context.Context) *tls.ConnectionState {
	p, _ := peer.FromContext(ctx)
	if p == nil || p.AuthInfo == nil {
		return nil
	}
	tlsCreds, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return &tlsCreds.State
}

// FromContext returns the RequestInfo from the context. This function will always return a (possibly zero) value.
func FromContext(ctx context.Context) RequestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return ri
}

func (h *Handler) extractFromMD(ctx context.Context) (*RequestInfo, error) {
	md := metautils.ExtractIncoming(ctx)
	riB64 := md.Get(requestInfoMDKey)
	if riB64 == "" {
		return nil, nil
	}

	if srcIP := sourceIP(ctx); srcIP == nil || !srcIP.IsLoopback() {
		return nil, fmt.Errorf("RequestInfo metadata received via non-local connection from %v", srcIP)
	}

	riRaw, err := base64.URLEncoding.DecodeString(riB64)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode request info")
	}

	riSigB64 := md.Get(requestInfoSigMDKey)
	riSig, err := base64.URLEncoding.DecodeString(riSigB64)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode request info signature")
	}

	if err := h.signer.Verify(riRaw, riSig); err != nil {
		return nil, errors.Wrap(err, "could not validate request info")
	}

	var serializedRI serializedRequestInfo
	if err := gob.NewDecoder(bytes.NewReader(riRaw)).Decode(&serializedRI); err != nil {
		return nil, errors.Wrap(err, "could not decode request info")
	}

	timeDelta := h.clock.SinceEpoch() - serializedRI.RequestMonotime
	if timeDelta < 0 || timeDelta > maxTimeDelta {
		log.Errorf("UNEXPECTED: decoded request info has invalid time delta %v", timeDelta)
		return nil, fmt.Errorf("decoded request info has invalid time delta %v", timeDelta)
	}

	return &serializedRI.RequestInfo, nil
}

// UpdateContextForGRPC provides the context updater logic when used with GRPC interceptors.
func (h *Handler) UpdateContextForGRPC(ctx context.Context) (context.Context, error) {
	ri, err := h.extractFromMD(ctx)
	if err != nil {
		// This should only happen if someone is trying to spoof a RequestInfo. Log, but don't return any details in the
		// error message.
		log.Errorf("error extracting RequestInfo from incoming metadata: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "malformed request")
	}

	tlsState := tlsStateFromContext(ctx)
	if ri == nil {
		ri = &RequestInfo{
			ClientUsedTLS: tlsState != nil,
		}
	}

	// Populate request info from TLS state.
	if tlsState != nil {
		ri.Hostname = tlsState.ServerName
		ri.VerifiedChains = extractCertInfoChains(tlsState.VerifiedChains)
	}

	ri.Metadata, _ = metadata.FromIncomingContext(ctx)
	return context.WithValue(ctx, requestInfoKey{}, *ri), nil
}

// HTTPIntercept provides a http interceptor logic for populating the context with the request info.
func (h *Handler) HTTPIntercept(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ri := &RequestInfo{
			Hostname:    r.Host,
			Metadata:    metadataFromHeader(r.Header),
			HTTPRequest: slimHTTPRequest(r),
		}
		// X-Forwarded-Host takes precedence in case we are behind a proxy.
		// `Hostname` should match what the client sees.
		if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
			ri.Hostname = fwdHost
		}
		if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
			ri.ClientUsedTLS = fwdProto != "http"
		} else {
			ri.ClientUsedTLS = r.TLS != nil
		}

		if r.TLS != nil {
			ri.VerifiedChains = extractCertInfoChains(r.TLS.VerifiedChains)
		}
		newCtx := context.WithValue(r.Context(), requestInfoKey{}, *ri)
		handler.ServeHTTP(w, r.WithContext(newCtx))
	})
}

func sourceIP(ctx context.Context) net.IP {
	p, _ := peer.FromContext(ctx)
	if p == nil {
		return nil
	}
	switch addr := p.Addr.(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	case *net.IPAddr:
		return addr.IP
	default:
		return nil
	}
}

func metadataFromHeader(header http.Header) metadata.MD {
	md := make(metadata.MD)
	for key, vals := range header {
		md.Append(key, vals...)
	}
	return md
}
