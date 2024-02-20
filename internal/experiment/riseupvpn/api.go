package riseupvpn

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/ooni/minivpn/pkg/config"
	"github.com/ooni/probe-cli/v3/internal/model"
)

//
// Parse RiseupVPN API responses.
//

const (
	eipServiceURL     = "https://api.black.riseup.net:443/3/config/eip-service.json"
	clientCertURL     = "https://api.black.riseup.net:443/3/cert"
	providerURL       = "https://riseup.net/provider.json"
	openvpnProto      = "openvpn"
	openvpnOBFS4Proto = "openvpn+obfs4"
)

var (
	errCannotGetVPNCert    = errors.New("err_fetch_openvpn_creds")
	errCannotGetVPNOptions = errors.New("err_parse_openvpn_config")
)

type OpenVPNOptions map[string]interface{}

// EIPServiceV3 is the main JSON object returned by eip-service.json.
type EIPServiceV3 struct {
	Gateways             []GatewayV3
	OpenVPNConfiguration OpenVPNOptions `json:"openvpn_configuration"`
}

// CapabilitiesV3 is a list of transports a gateway supports
type CapabilitiesV3 struct {
	Transport []TransportV3
}

// GatewayV3 describes a gateway.
type GatewayV3 struct {
	Capabilities CapabilitiesV3
	Host         string
	IPAddress    string `json:"ip_address"`
}

// TransportV3 describes a transport.
type TransportV3 struct {
	Type      string
	Protocols []string
	Ports     []string
	Options   map[string]string
}

// openVPNCredentials holds the CA, Cert and Key for riseupvpn service.
type openVPNCredentials struct {
	ca   []byte
	cert []byte
	key  []byte
}

func generateEndpoints(gateways []GatewayV3, transportType string) []*Endpoint {
	// TODO: add needed Config for bridge too
	endpoints := []*Endpoint{}

	for _, gateway := range gateways {
		for _, transport := range gateway.Capabilities.Transport {
			if transport.Type != transportType {
				continue
			}
			for _, port := range transport.Ports {
				var vpnproto string
				switch transportType {
				case "obfs4":
					vpnproto = openvpnOBFS4Proto
				case "openvpn":
					vpnproto = openvpnProto
				}
				for _, proto := range transport.Protocols {
					endpoint := &Endpoint{
						Protocol:  vpnproto,
						IP:        gateway.IPAddress,
						Port:      port,
						Transport: config.Proto(proto),
					}
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}
	return endpoints
}

func getResponseForURL(tk *TestKeys, url string) string {
	for _, request := range tk.Requests {
		if request.Request.URL == url && request.Failure == nil {
			return string(request.Response.Body)
		}
	}
	return ""
}

func parseGateways(tk *TestKeys) []GatewayV3 {
	response := getResponseForURL(tk, eipServiceURL)
	// TODO(bassosimone,cyberta): is it reasonable that we discard
	// the error when the JSON we fetched cannot be parsed?
	// See https://github.com/ooni/probe/issues/1432
	eipService, err := DecodeEIPServiceV3(response)
	if err == nil {
		return eipService.Gateways
	}
	return nil
}

func parseOpenVPNOptions(tk *TestKeys) (OpenVPNOptions, error) {
	response := getResponseForURL(tk, eipServiceURL)
	eipService, err := DecodeEIPServiceV3(response)
	if err == nil {
		return eipService.OpenVPNConfiguration, nil
	}
	return nil, errCannotGetVPNOptions
}

// updateCredsFromCertResponse takes a byte array containing both a RSA private key
// and a certificate, as returned by riseupvpn api, and writes the private key and the
// certificate into the passed credentials object.
func updateCredsFromCertResponse(creds *openVPNCredentials, pemData []byte) bool {
	maybeUpdateBlock := func(block *pem.Block, key, cert *bytes.Buffer) {
		if block.Type == "RSA PRIVATE KEY" {
			pem.Encode(key, block)
		}
		if block.Type == "CERTIFICATE" {
			pem.Encode(cert, block)
		}

	}
	cert := &bytes.Buffer{}
	key := &bytes.Buffer{}

	if len(pemData) == 0 {
		return false
	}

	block, rest := pem.Decode(pemData)
	if block == nil {
		return false
	}
	maybeUpdateBlock(block, key, cert)

	block, _ = pem.Decode(rest)
	if block == nil {
		return false
	}
	maybeUpdateBlock(block, key, cert)

	creds.cert = cert.Bytes()
	creds.key = key.Bytes()
	return true
}

func parseOpenVPNCredentials(tk *TestKeys, pemCA []byte) (*openVPNCredentials, error) {
	creds := &openVPNCredentials{}
	creds.ca = []byte(pemCA)

	if ok := updateCredsFromCertResponse(creds, []byte(getResponseForURL(tk, clientCertURL))); !ok {
		return nil, errCannotGetVPNCert
	}
	return creds, nil
}

// DecodeEIPServiceV3 decodes eip-service.json version 3
func DecodeEIPServiceV3(body string) (*EIPServiceV3, error) {
	var eip EIPServiceV3
	err := json.Unmarshal([]byte(body), &eip)
	if err != nil {
		return nil, err
	}
	return &eip, nil
}

// NewExperimentMeasurer creates a new ExperimentMeasurer.
func NewExperimentMeasurer(config Config) model.ExperimentMeasurer {
	return Measurer{Config: config}
}
