package openvpn

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"slices"
	"strings"

	vpnconfig "github.com/ooni/minivpn/pkg/config"
	vpntracex "github.com/ooni/minivpn/pkg/tracex"
	"github.com/ooni/probe-cli/v3/internal/model"
)

var (
	// ErrBadBase64Blob is the error returned when we cannot decode an option passed as base64.
	ErrBadBase64Blob = errors.New("wrong base64 encoding")
)

// endpoint is a single endpoint to be probed.
// The information contained in here is not sufficient to complete a connection:
// we need to augment it with more info, as cipher selection or obfuscating proxy credentials.
type endpoint struct {
	// IPAddr is the IP Address for this endpoint.
	IPAddr string

	// Obfuscation is any obfuscation method use to connect to this endpoint.
	// Valid values are: obfs4, none.
	Obfuscation string

	// Port is the Port for this endpoint.
	Port string

	// Protocol is the tunneling protocol (openvpn, openvpn+obfs4).
	Protocol string

	// Provider is a unique label identifying the provider maintaining this endpoint.
	Provider string

	// Transport is the underlying transport used for this endpoint. Valid transports are `tcp` and `udp`.
	Transport string
}

// newEndpointFromInputString constructs an endpoint after parsing an input string.
//
// The input URI is in the form:
// "openvpn://provider.corp/?address=1.2.3.4:1194&transport=udp
// "openvpn+obfs4://provider.corp/address=1.2.3.4:1194?&cert=deadbeef&iat=0"
func newEndpointFromInputString(uri string) (*endpoint, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, err)
	}
	var obfuscation string
	switch parsedURL.Scheme {
	case "openvpn":
		obfuscation = "none"
	case "openvpn+obfs4":
		obfuscation = "obfs4"
	default:
		return nil, fmt.Errorf("%w: unknown scheme: %s", ErrInvalidInput, parsedURL.Scheme)
	}

	provider := strings.TrimSuffix(parsedURL.Hostname(), ".corp")
	if provider == "" {
		return nil, fmt.Errorf("%w: expected provider as host: %s", ErrInvalidInput, parsedURL.Host)
	}
	if !isValidProvider(provider) {
		return nil, fmt.Errorf("%w: unknown provider: %s", ErrInvalidInput, provider)
	}

	params := parsedURL.Query()

	transport := params.Get("transport")
	if transport != "tcp" && transport != "udp" {
		return nil, fmt.Errorf("%w: invalid transport: %s", ErrInvalidInput, transport)
	}

	address := params.Get("address")
	if address == "" {
		return nil, fmt.Errorf("%w: please specify an address as part of the input", ErrInvalidInput)
	}
	ip, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot split ip:port", ErrInvalidInput)
	}
	if parsedIP := net.ParseIP(ip); parsedIP == nil {
		return nil, fmt.Errorf("%w: bad ip", ErrInvalidInput)
	}

	endpoint := &endpoint{
		IPAddr:      ip,
		Port:        port,
		Obfuscation: obfuscation,
		Protocol:    "openvpn",
		Provider:    provider,
		Transport:   transport,
	}
	return endpoint, nil
}

// String implements [fmt.Stringer]. This is a compact representation of the endpoint,
// which differs from the input URI scheme. This is the canonical representation, that can be used
// to deterministically slice a list of endpoints, sort them lexicographically, etc.
func (e *endpoint) String() string {
	var proto string
	if e.Obfuscation == "obfs4" {
		proto = e.Protocol + "+obfs4"
	} else {
		proto = e.Protocol
	}
	url := &url.URL{
		Scheme: proto,
		Host:   net.JoinHostPort(e.IPAddr, e.Port),
		Path:   e.Transport,
	}
	return url.String()
}

// AsInputURI is a string representation of this endpoint, as used in the experiment input URI format.
func (e *endpoint) AsInputURI() string {
	var proto string
	if e.Obfuscation == "obfs4" {
		proto = e.Protocol + "+obfs4"
	} else {
		proto = e.Protocol
	}

	provider := e.Provider
	if provider == "" {
		provider = "unknown"
	}

	values := map[string][]string{
		"address":   {net.JoinHostPort(e.IPAddr, e.Port)},
		"transport": {e.Transport},
	}

	url := &url.URL{
		Scheme:   proto,
		Host:     provider + ".corp",
		RawQuery: url.Values(values).Encode(),
	}
	return url.String()
}

// endpointList is a list of endpoints.
type endpointList []*endpoint

// DefaultEndpoints contains a subset of known endpoints to be used if no input is passed to the experiment and
// the backend query fails for whatever reason. We risk distributing endpoints that can go stale, so we should be careful about
// the stability of the endpoints selected here, but in restrictive environments it's useful to have something
// to probe in absence of an useful OONI API. Valid credentials are still needed, though.
var DefaultEndpoints = endpointList{
	{
		Provider:  "riseup",
		IPAddr:    "51.15.187.53",
		Port:      "1194",
		Protocol:  "openvpn",
		Transport: "tcp",
	},
	{
		Provider:  "riseup",
		IPAddr:    "51.15.187.53",
		Port:      "1194",
		Protocol:  "openvpn",
		Transport: "udp",
	},
}

// Shuffle randomizes the order of items in the endpoint list.
func (e endpointList) Shuffle() endpointList {
	rand.Shuffle(len(e), func(i, j int) {
		e[i], e[j] = e[j], e[i]
	})
	return e
}

// APIEnabledProviders is the list of providers that the stable API Endpoint knows about.
// This array will be a subset of the keys in defaultOptionsByProvider, but it might make sense
// to still register info about more providers that the API officially knows about.
var APIEnabledProviders = []string{
	// TODO(ainghazal): fix the backend so that we can remove the spurious "vpn" suffix here.
	"riseupvpn",
}

// isValidProvider returns true if the provider is found as key in the array of APIEnabledProviders
func isValidProvider(provider string) bool {
	return slices.Contains(APIEnabledProviders, provider)
}

// mergeOpenVPNConfig gets a properly configured [*vpnconfig.Config] object for the given endpoint.
// To obtain that, we merge the endpoint specific configuration with the options passed as richer input targets.
func mergeOpenVPNConfig(
	tracer *vpntracex.Tracer,
	logger model.Logger,
	endpoint *endpoint,
	config *Config) (*vpnconfig.Config, error) {

	// TODO(ainghazal): use merge ability in vpnconfig.OpenVPNOptions merge (pending PR)
	provider := endpoint.Provider
	if !isValidProvider(provider) {
		return nil, fmt.Errorf("%w: unknown provider: %s", ErrInvalidInput, provider)
	}

	cfg := vpnconfig.NewConfig(
		vpnconfig.WithLogger(logger),
		vpnconfig.WithOpenVPNOptions(
			&vpnconfig.OpenVPNOptions{
				// endpoint-specific options.
				Remote: endpoint.IPAddr,
				Port:   endpoint.Port,
				Proto:  vpnconfig.Proto(endpoint.Transport),

				// options and credentials come from the experiment
				// richer input targets.
				Cipher: config.Cipher,
				Auth:   config.Auth,
				CA:     []byte(config.SafeCA),
				Cert:   []byte(config.SafeCert),
				Key:    []byte(config.SafeKey),
			},
		),
		vpnconfig.WithHandshakeTracer(tracer),
	)

	return cfg, nil
}

func isValidProtocol(s string) bool {
	if strings.HasPrefix(s, "openvpn://") {
		return true
	}
	if strings.HasPrefix(s, "openvpn+obfs4://") {
		return true
	}
	return false
}
