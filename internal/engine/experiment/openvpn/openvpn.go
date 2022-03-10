// Package openvpn contains the openvpn experiment. This experiment
// measures the bootstrapping of an OpenVPN connection against a given remote.
//
// See https://github.com/ooni/spec/blob/master/nettests/ts-032-openvpn.md
package openvpn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/tunnel"

	"github.com/ainghazal/minivpn/vpn"
)

const (
	// testName is the name of this experiment
	testName = "openvpn"

	// testVersion is the openvpn experiment version.
	testVersion = "0.0.1"
)

// Config contains the experiment config.
type Config struct {
	ConfigFile string `ooni:"Configuration file for the OpenVPN experiment"`
}

// TestKeys contains the experiment's result.
type TestKeys struct {
	// BootstrapTime contains the bootstrap time on success.
	BootstrapTime float64 `json:"bootstrap_time"`

	// Failure contains the failure string or nil.
	Failure *string `json:"failure"`

	// VPNLogs contains the bootstrap logs.
	VPNLogs []string `json:"vpn_logs"`

	// MiniVPNVersion contains the version of the minivpn library used.
	MiniVPNVersion string `json:"minivpn_version"`

	// just to capture something for now..
	Response string `json:"wtfip_response"`
}

// Measurer performs the measurement.
type Measurer struct {
	// config contains the experiment settings.
	config Config

	// mockStartListener is an optional function that allows us to override
	// the function we actually use to start the ptx listener.
	//mockStartListener func() error

	// mockStartTunnel is an optional function that allows us to override the
	// default tunnel.Start function used to start a tunnel.
	//mockStartTunnel func(
	//	ctx context.Context, config *tunnel.Config) (tunnel.Tunnel, tunnel.DebugInfo, error)
}

// ExperimentName implements model.ExperimentMeasurer.ExperimentName.
func (m *Measurer) ExperimentName() string {
	return testName
}

// ExperimentVersion implements model.ExperimentMeasurer.ExperimentVersion.
func (m *Measurer) ExperimentVersion() string {
	return testVersion
}

// registerExtensions registers the extensions used by this experiment.
func (m *Measurer) registerExtensions(measurement *model.Measurement) {
	// currently none
}

// Run runs the experiment with the specified context, session,
// measurement, and experiment calbacks. This method should only
// return an error in case the experiment could not run (e.g.,
// a required input is missing). Otherwise, the code should just
// set the relevant OONI error inside of the measurement and
// return nil. This is important because the caller may not submit
// the measurement if this method returns an error.
func (m *Measurer) Run(
	ctx context.Context, sess model.ExperimentSession,
	measurement *model.Measurement, callbacks model.ExperimentCallbacks,
) error {
	config := string(measurement.Input)
	dialer, err := m.setup(ctx, config, sess.Logger())
	if err != nil {
		// we cannot setup the experiment
		// TODO this includes if we don't have the correct certificates etc.
		// This means that we need to get the cert material ahead of time.
		return err
	}
	m.registerExtensions(measurement)
	//start := time.Now()
	const maxRuntime = 600 * time.Second
	ctx, cancel := context.WithTimeout(ctx, maxRuntime)
	defer cancel()
	tkch := make(chan *TestKeys)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// TODO need to pass the timeout-context to the dialer.
	go m.bootstrap(ctx, sess, tkch, dialer)

	for {
		select {
		case tk := <-tkch:
			measurement.TestKeys = tk
			callbacks.OnProgress(1.0, testName+" experiment is finished")
			return nil
		}
		// todo: report progress...
	}
}

// setup prepares for running the openvpn experiment. Returns a minivpn dialer on success.
// Returns an error on failure.
func (m *Measurer) setup(ctx context.Context, config string, logger model.Logger) (*vpn.RawDialer, error) {
	// TODO - pass context to dialer
	o, err := vpn.ParseConfigFile(config)
	if err != nil {
		return nil, err
	}
	raw := vpn.NewRawDialer(o)
	return raw, nil
}

// bootstrap runs the bootstrap.
func (m *Measurer) bootstrap(ctx context.Context, sess model.ExperimentSession,
	out chan<- *TestKeys, raw *vpn.RawDialer) {
	tk := &TestKeys{
		BootstrapTime: 0,
		Failure:       nil,
	}
	sess.Logger().Infof(
		"openvpn: hello world this is logging: %+v", true)
	defer func() {
		out <- tk
	}()

	s := time.Now()

	raw.Dial()

	tk.BootstrapTime = time.Now().Sub(s).Seconds()

	d := vpn.NewDialer(raw)

	// TODO split into pinger + urlgrabber functions

	client := http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
		},
	}
	resp, err := client.Get("https://wtfismyip.com/json")
	if err != nil {
		// Note: archival.NewFailure scrubs IP addresses
		tk.Failure = archival.NewFailure(err)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tk.Failure = archival.NewFailure(err)
		return
	}
	tk.Response = string(body)
	tk.MiniVPNVersion = getMiniVPNVersion()
}

// baseTunnelDir returns the base directory to use for tunnelling
func (m *Measurer) baseTunnelDir(sess model.ExperimentSession) string {
	return sess.TunnelDir()
}

// startListener either calls f or mockStartListener depending
// on whether mockStartListener is nil or not.
func (m *Measurer) startListener(f func() error) error {
	//if m.mockStartListener != nil {
	//	return m.mockStartListener()
	//}
	return f()
}

// startTunnel returns the proper function to start a tunnel.
func (m *Measurer) startTunnel() func(
	ctx context.Context, config *tunnel.Config) (tunnel.Tunnel, tunnel.DebugInfo, error) {
	//if m.mockStartTunnel != nil {
	//	return m.mockStartTunnel
	//}
	return tunnel.Start
}

// NewExperimentMeasurer creates a new ExperimentMeasurer.
func NewExperimentMeasurer(config Config) model.ExperimentMeasurer {
	return &Measurer{config: config}
}

// SummaryKeys contains summary keys for this experiment.
//
// Note that this structure is part of the ABI contract with probe-cli
// therefore we should be careful when changing it.
type SummaryKeys struct {
	IsAnomaly bool `json:"-"`
}

var (
	// errInvalidTestKeysType indicates the test keys type is invalid.
	errInvalidTestKeysType = errors.New("openvpn: invalid test keys type")

	//errNilTestKeys indicates that the test keys are nil.
	errNilTestKeys = errors.New("openvpn: nil test keys")
)

// GetSummaryKeys implements model.ExperimentMeasurer.GetSummaryKeys.
func (m *Measurer) GetSummaryKeys(measurement *model.Measurement) (interface{}, error) {
	testkeys, good := measurement.TestKeys.(*TestKeys)
	if !good {
		return nil, errInvalidTestKeysType
	}
	if testkeys == nil {
		return nil, errNilTestKeys
	}
	return SummaryKeys{IsAnomaly: testkeys.Failure != nil}, nil
}

func getMiniVPNVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range bi.Deps {
		p := strings.Split(dep.Path, "/")
		if p[len(p)-1] == "minivpn" {
			return dep.Version
		}
	}
	return ""
}
