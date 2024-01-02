package internaltov2storage

import (
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
)

func ComplianceOperatorRule(sensorData *central.ComplianceOperatorRuleV2, clusterID string) *storage.ComplianceOperatorRuleV2 {
	return &storage.ComplianceOperatorRuleV2{
		Id:          sensorData.GetRuleUid(),
		RuleId:      sensorData.GetRuleId(),
		Name:        sensorData.GetName(),
		RuleType:    sensorData.GetRuleType(),
		Severity:    0,
		Labels:      sensorData.GetLabels(),
		Annotations: sensorData.GetAnnotations(),
		Title:       sensorData.GetTitle(),
		Description: sensorData.GetDescription(),
		Rationale:   sensorData.GetRationale(),
		Fixes:       nil,
		Warning:     sensorData.Warning,
		Controls:    nil,
		ClusterId:   clusterID,
	}
}
