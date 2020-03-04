package checkcm6

import (
	"github.com/stackrox/rox/central/compliance/checks/common"
	"github.com/stackrox/rox/central/compliance/framework"
	"github.com/stackrox/rox/pkg/features"
)

const (
	controlID = "NIST_SP_800_53:CM_6"

	interpretationText = `This control requires that configuration controls be implemented and deviations are documented.

For this control, ` + common.CheckNoViolationsForDeployPhasePoliciesInterpretation + `

To approve a deviation, resolve the policy violation or adjust the scope or whitelist for the policy.`
)

func init() {
	framework.MustRegisterNewCheckIfFlagEnabled(
		framework.CheckMetadata{
			ID:                 controlID,
			Scope:              framework.ClusterKind,
			DataDependencies:   []string{"Policies", "UnresolvedAlerts"},
			InterpretationText: interpretationText,
		},
		func(ctx framework.ComplianceContext) {
			common.CheckNoViolationsForDeployPhasePolicies(ctx)
		}, features.NistSP800_53)
}
