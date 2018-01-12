package kubelet

import (
	"bitbucket.org/stack-rox/apollo/generated/api/v1"
	"bitbucket.org/stack-rox/apollo/pkg/checks"
	"bitbucket.org/stack-rox/apollo/pkg/checks/utils"
)

type caFileOwnership struct{}

func (c *caFileOwnership) Definition() utils.Definition {
	return utils.Definition{
		CheckDefinition: v1.CheckDefinition{
			Name:        "CIS Kubernetes v1.2.0 - 2.2.8",
			Description: "Ensure that the client certificate authorities file ownership is set to root:root",
		}, Dependencies: []utils.Dependency{utils.InitKubeletConfig},
	}
}

func (c *caFileOwnership) Run() (result v1.CheckResult) {
	utils.Pass(&result)
	params, ok := utils.KubeletConfig.Get("client-ca-file")
	if !ok {
		utils.Warn(&result)
		utils.AddNotes(&result, "Cannot check kubelet CA file ownership because kubelet command line does not define 'client-ca-file' parameter")
		return
	}

	result = utils.NewOwnershipCheck("", "", params.String(), "root", "root").Run()
	return
}

// NewCAFileOwnership implements CIS Kubernetes v1.2.0 2.2.8
func NewCAFileOwnership() utils.Check {
	return &caFileOwnership{}
}

func init() {
	checks.AddToRegistry(NewCAFileOwnership())
}
