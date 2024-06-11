package openvpn

import (
	"context"
	"fmt"

	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/reflectx"
	"github.com/ooni/probe-cli/v3/internal/targetloading"
)

// defaultProvider is the provider we will request from API in case we got no provider set
// in the CLI options.
var defaultProvider = "riseupvpn"

// providerAuthentication is a map so that we know which kind of credentials we
// need to fill in the openvpn options for each known provider.
var providerAuthentication = map[string]AuthMethod{
	"riseupvpn":     AuthCertificate,
	"tunnelbearvpn": AuthUserPass,
	"surfsharkvpn":  AuthUserPass,
}

// Target is a richer-input target that this experiment should measure.
type Target struct {
	// Options contains the configuration.
	Options *Config

	// URL is the input URL.
	URL string
}

var _ model.ExperimentTarget = &Target{}

// Category implements [model.ExperimentTarget].
func (t *Target) Category() string {
	return model.DefaultCategoryCode
}

// Country implements [model.ExperimentTarget].
func (t *Target) Country() string {
	return model.DefaultCountryCode
}

// Input implements [model.ExperimentTarget].
func (t *Target) Input() string {
	return t.URL
}

// String implements [model.ExperimentTarget].
func (t *Target) String() string {
	return t.URL
}

// NewLoader constructs a new [model.ExperimentTargerLoader] instance.
//
// This function PANICS if options is not an instance of [*openvpn.Config].
func NewLoader(loader *targetloading.Loader, gopts any) model.ExperimentTargetLoader {
	// Panic if we cannot convert the options to the expected type.
	//
	// We do not expect a panic here because the type is managed by the registry package.
	options := gopts.(*Config)

	// Construct the proper loader instance.
	return &targetLoader{
		loader:  loader,
		options: options,
		session: loader.Session,
	}
}

// targetLoader loads targets for this experiment.
type targetLoader struct {
	loader  *targetloading.Loader
	options *Config
	session targetloading.Session
}

// Load implements model.ExperimentTargetLoader.
func (tl *targetLoader) Load(ctx context.Context) ([]model.ExperimentTarget, error) {
	// If inputs and files are all empty and there are no options, let's use the backend
	if len(tl.loader.StaticInputs) <= 0 && len(tl.loader.SourceFiles) <= 0 &&
		reflectx.StructOrStructPtrIsZero(tl.options) {
		return tl.loadFromBackend(ctx)
	}

	// Otherwise, attempt to load the static inputs from CLI and files
	inputs, err := targetloading.LoadStatic(tl.loader)

	// Handle the case where we couldn't load from CLI or files
	if err != nil {
		return nil, err
	}

	// Build the list of targets that we should measure.
	var targets []model.ExperimentTarget
	for _, input := range inputs {
		targets = append(targets, &Target{
			Options: tl.options,
			URL:     input,
		})
	}
	return targets, nil
}

// TODO(ainghazal): we might want to get both the BaseURL and the HTTPClient from the session,
// and then deal with the openvpn-specific API calls ourselves within the boundaries of the experiment.
func (tl *targetLoader) loadFromBackend(_ context.Context) ([]model.ExperimentTarget, error) {
	if tl.options.Provider == "" {
		tl.options.Provider = defaultProvider
	}

	targets := make([]model.ExperimentTarget, 0)
	provider := tl.options.Provider

	// TODO(ainghazal): pass country code too (from session?)
	apiConfig, err := tl.session.FetchOpenVPNConfig(context.Background(), provider, "XX")
	if err != nil {
		return nil, err
	}

	auth, ok := providerAuthentication[provider]
	if !ok {
		return nil, fmt.Errorf("%w: unknown authentication for provider %s", ErrInvalidInput, provider)
	}

	for _, input := range apiConfig.Inputs {
		config := &Config{
			// Auth and Cipher are hardcoded for now.
			Auth:   "SHA512",
			Cipher: "AES-256-GCM",
		}
		switch auth {
		case AuthCertificate:
			config.SafeCA = apiConfig.Config.CA
			config.SafeCert = apiConfig.Config.Cert
			config.SafeKey = apiConfig.Config.Key
		}
		targets = append(targets, &Target{
			URL:     input,
			Options: config,
		})
	}

	return targets, nil
}
