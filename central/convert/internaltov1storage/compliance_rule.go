package internaltov1storage

import (
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
)

var (
	log = logging.LoggerForModule()
)

// ComplianceOperatorRule converts message from sensor to V1 storage
func ComplianceOperatorRule(sensorData *central.ComplianceOperatorRuleV2, clusterID string) *storage.ComplianceOperatorRule {
	log.Info("SHREWS -- in V1 converter")
	return &storage.ComplianceOperatorRule{
		Id:          sensorData.GetRuleUid(),
		RuleId:      sensorData.GetRuleId(),
		Name:        sensorData.GetName(),
		ClusterId:   clusterID,
		Labels:      sensorData.GetLabels(),
		Annotations: sensorData.GetAnnotations(),
		Title:       sensorData.GetTitle(),
		Description: sensorData.GetDescription(),
		Rationale:   sensorData.GetRationale(),
	}
}
