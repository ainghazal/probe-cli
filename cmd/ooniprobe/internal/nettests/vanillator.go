package nettests

import "github.com/ooni/probe-cli/v3/internal/model"

// VanillaTor test implementation
type VanillaTor struct {
}

// Run starts the test
func (h VanillaTor) Run(ctl *Controller) error {
	builder, err := ctl.Session.NewExperimentBuilder("vanilla_tor")
	if err != nil {
		return err
	}
	return ctl.Run(builder, []model.ExperimentTarget{model.NewOOAPIURLInfoWithDefaultCategoryAndCountry("")})
}

func (h VanillaTor) onlyBackground() {}
