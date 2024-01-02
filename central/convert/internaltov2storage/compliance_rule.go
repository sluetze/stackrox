package internaltov2storage

import (
	"strings"

	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
)

const (
	standardsKey = "policies.open-cluster-management.io/standards"

	controlAnnotationBase = "control.compliance.openshift.io/"
)

var (
	log = logging.LoggerForModule()
)

// ComplianceOperatorRule converts message from sensor to V2 storage
func ComplianceOperatorRule(sensorData *central.ComplianceOperatorRuleV2, clusterID string) *storage.ComplianceOperatorRuleV2 {
	log.Info("SHREWS -- in v2 converter")
	fixes := make([]*storage.ComplianceOperatorRuleV2_Fix, len(sensorData.Fixes))
	for _, fix := range sensorData.Fixes {
		fixes = append(fixes, &storage.ComplianceOperatorRuleV2_Fix{
			Platform:   fix.GetPlatform(),
			Disruption: fix.GetDisruption(),
		})
	}
	log.Info("SHREWS -- in v2 converter -- done with fixes")

	// TODO:  figure out where to grab this.  Basically is policies.open-cluster-management.io/standards legit to
	// grab the standards so that then we can get the controls via control.compliance.openshift.io/STANDARD
	standards := strings.Split(sensorData.GetAnnotations()[standardsKey], ",")
	controls := make([]*storage.RuleControls, len(standards))
	for _, standard := range standards {
		controls = append(controls, &storage.RuleControls{
			Standard: standard,
			Controls: strings.Split(sensorData.GetAnnotations()[controlAnnotationBase+standard], ","),
		})
	}
	log.Info("SHREWS -- in v2 converter -- done with controls")

	return &storage.ComplianceOperatorRuleV2{
		Id:          sensorData.GetRuleUid(),
		RuleId:      sensorData.GetRuleId(),
		Name:        sensorData.GetName(),
		RuleType:    sensorData.GetRuleType(),
		Severity:    severityToV2[sensorData.GetSeverity()],
		Labels:      sensorData.GetLabels(),
		Annotations: sensorData.GetAnnotations(),
		Title:       sensorData.GetTitle(),
		Description: sensorData.GetDescription(),
		Rationale:   sensorData.GetRationale(),
		Fixes:       fixes,
		Warning:     sensorData.GetWarning(),
		Controls:    controls,
		ClusterId:   clusterID,
	}
}
