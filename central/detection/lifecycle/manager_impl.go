package lifecycle

import (
	"fmt"
	"sync"
	"time"

	"github.com/deckarep/golang-set"
	"github.com/gogo/protobuf/proto"
	deploymentDatastore "github.com/stackrox/rox/central/deployment/datastore"
	"github.com/stackrox/rox/central/detection/deploytime"
	"github.com/stackrox/rox/central/detection/runtime"
	"github.com/stackrox/rox/central/detection/utils"
	"github.com/stackrox/rox/central/enrichment"
	processIndicatorDatastore "github.com/stackrox/rox/central/processindicator/datastore"
	"github.com/stackrox/rox/central/sensorevent/service/pipeline"
	"github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/policies"
	"github.com/stackrox/rox/pkg/set"
	"golang.org/x/time/rate"
)

type indicatorWithInjector struct {
	indicator           *v1.ProcessIndicator
	enforcementInjector pipeline.EnforcementInjector
}

type managerImpl struct {
	enricher           enrichment.Enricher
	runtimeDetector    runtime.Detector
	deploytimeDetector deploytime.Detector
	alertManager       utils.AlertManager

	deploymentDataStore deploymentDatastore.DataStore
	processesDataStore  processIndicatorDatastore.DataStore

	queuedIndicators map[string]indicatorWithInjector

	queueLock           sync.Mutex
	flushProcessingLock sync.Mutex

	limiter *rate.Limiter
	ticker  *time.Ticker
}

func (m *managerImpl) copyAndResetIndicatorQueue() map[string]indicatorWithInjector {
	m.queueLock.Lock()
	defer m.queueLock.Unlock()
	if len(m.queuedIndicators) == 0 {
		return nil
	}
	copiedMap := m.queuedIndicators
	m.queuedIndicators = make(map[string]indicatorWithInjector)

	return copiedMap
}

func (m *managerImpl) flushQueuePeriodically() {
	defer m.ticker.Stop()
	for range m.ticker.C {
		m.flushIndicatorQueue()
	}
}

func (m *managerImpl) flushIndicatorQueue() {
	m.flushProcessingLock.Lock()
	defer m.flushProcessingLock.Unlock()

	copiedQueue := m.copyAndResetIndicatorQueue()
	if len(copiedQueue) == 0 {
		return
	}

	// Map copiedQueue to slice
	indicatorSlice := make([]*v1.ProcessIndicator, 0, len(copiedQueue))
	for _, i := range copiedQueue {
		indicatorSlice = append(indicatorSlice, i.indicator)
	}

	// Index the process indicators in batch
	if err := m.processesDataStore.AddProcessIndicators(indicatorSlice...); err != nil {
		logger.Errorf("Error adding process indicators: %v", err)
	}

	deploymentIDs := uniqueDeploymentIDs(copiedQueue)
	newAlerts, err := m.runtimeDetector.AlertsForDeployments(deploymentIDs...)
	if err != nil {
		logger.Errorf("Failed to compute runtime alerts: %s", err)
		return
	}

	oldAlerts, err := m.alertManager.GetAlertsByLifecycleAndDeployments(v1.LifecycleStage_RUNTIME, deploymentIDs...)
	if err != nil {
		logger.Errorf("Failed to retrieve old runtime alerts: %s", err)
		return
	}

	err = m.alertManager.AlertAndNotify(oldAlerts, newAlerts)
	if err != nil {
		logger.Errorf("Couldn't alert and notify: %s", err)
	}

	containersSet := containersToKill(newAlerts, copiedQueue)
	for _, indicatorInfo := range containersSet {
		info := indicatorInfo.indicator
		deployment, exists, err := m.deploymentDataStore.GetDeployment(info.GetDeploymentId())
		if err != nil {
			logger.Errorf("Couldn't enforce on deployment %s: failed to retrieve: %s", info.GetDeploymentId(), err)
			continue
		}
		if !exists {
			logger.Errorf("Couldn't enforce on deployment %s: not found in store", info.GetDeploymentId())
			continue
		}
		enforcementAction := createEnforcementAction(deployment, info.GetSignal().GetContainerId())
		if enforcementAction == nil {
			logger.Errorf("Couldn't enforce on container %s, not found in deployment %s/%s", info.GetSignal().GetContainerId(),
				deployment.GetNamespace(), deployment.GetName())
			continue
		}
		injected := indicatorInfo.enforcementInjector.InjectEnforcement(enforcementAction)
		if !injected {
			logger.Errorf("Failed to inject enforcement action: %s", proto.MarshalTextString(enforcementAction))
		}
	}
}

func (m *managerImpl) addToQueue(indicator *v1.ProcessIndicator, injector pipeline.EnforcementInjector) {
	m.queueLock.Lock()
	defer m.queueLock.Unlock()

	m.queuedIndicators[indicator.GetId()] = indicatorWithInjector{
		indicator:           indicator,
		enforcementInjector: injector,
	}
}

func (m *managerImpl) IndicatorAdded(indicator *v1.ProcessIndicator, injector pipeline.EnforcementInjector) error {
	if indicator.GetId() == "" {
		return fmt.Errorf("invalid indicator received: %s, id was empty", proto.MarshalTextString(indicator))
	}

	m.addToQueue(indicator, injector)

	if m.limiter.Allow() {
		go m.flushIndicatorQueue()
	}
	return nil
}

func (m *managerImpl) DeploymentUpdated(deployment *v1.Deployment) (string, v1.EnforcementAction, error) {
	// Attempt to enrich the image before detection.
	if _, err := m.enricher.Enrich(deployment); err != nil {
		logger.Errorf("Error enriching deployment %s: %s", deployment.GetName(), err)
	}

	// Asynchronously update risk after processing.
	defer m.enricher.ReprocessDeploymentRiskAsync(deployment)

	presentAlerts, err := m.deploytimeDetector.AlertsForDeployment(deployment)
	if err != nil {
		return "", v1.EnforcementAction_UNSET_ENFORCEMENT, fmt.Errorf("fetching deploy time alerts: %s", err)
	}

	// Get the previous alerts for the deployment (if any exist).
	previousAlerts, err := m.alertManager.GetAlertsByLifecycleAndDeployments(v1.LifecycleStage_DEPLOY, deployment.GetId())
	if err != nil {
		return "", v1.EnforcementAction_UNSET_ENFORCEMENT, err
	}

	// Perform notifications and update DB.
	if err := m.alertManager.AlertAndNotify(previousAlerts, presentAlerts); err != nil {
		return "", v1.EnforcementAction_UNSET_ENFORCEMENT, err
	}

	// Generate enforcement actions based on the currently generated alerts.
	alertToEnforce, enforcementAction := determineEnforcement(presentAlerts)
	return alertToEnforce, enforcementAction, nil
}

func (m *managerImpl) UpsertPolicy(policy *v1.Policy) error {
	// Asynchronously update all deployments' risk after processing.
	defer m.enricher.ReprocessRiskAsync()

	var presentAlerts []*v1.Alert

	// Add policy to set.
	if policies.AppliesAtDeployTime(policy) {
		if err := m.deploytimeDetector.UpsertPolicy(policy); err != nil {
			return fmt.Errorf("adding policy %s to deploy time detector: %s", policy.GetName(), err)
		}
		deployTimeAlerts, err := m.deploytimeDetector.AlertsForPolicy(policy.GetId())
		if err != nil {
			return fmt.Errorf("error generating deploy-time alerts for policy %s: %s", policy.GetName(), err)
		}
		presentAlerts = append(presentAlerts, deployTimeAlerts...)
	} else {
		err := m.deploytimeDetector.RemovePolicy(policy.GetId())
		if err != nil {
			return fmt.Errorf("removing policy %s from deploy time detector: %s", policy.GetName(), err)
		}
	}

	if policies.AppliesAtRunTime(policy) {
		if err := m.runtimeDetector.UpsertPolicy(policy); err != nil {
			return fmt.Errorf("adding policy %s to runtime detector: %s", policy.GetName(), err)
		}
		runTimeAlerts, err := m.runtimeDetector.AlertsForPolicy(policy.GetId())
		if err != nil {
			return fmt.Errorf("error generating runtime alerts for policy %s: %s", policy.GetName(), err)
		}
		presentAlerts = append(presentAlerts, runTimeAlerts...)
	} else {
		err := m.runtimeDetector.RemovePolicy(policy.GetId())
		if err != nil {
			return fmt.Errorf("removing policy %s from runtime detector: %s", policy.GetName(), err)
		}
	}

	// Get any alerts previously existing for the policy (if any exist).
	previousAlerts, err := m.alertManager.GetAlertsByPolicy(policy.GetId())
	if err != nil {
		return err
	}

	// Perform notifications and update DB.
	return m.alertManager.AlertAndNotify(previousAlerts, presentAlerts)
}

func (m *managerImpl) DeploymentRemoved(deployment *v1.Deployment) error {
	oldAlerts, err := m.alertManager.GetAlertsByDeployment(deployment.GetId())
	if err != nil {
		return err
	}
	return m.alertManager.AlertAndNotify(oldAlerts, nil)
}

func (m *managerImpl) RemovePolicy(policyID string) error {
	if err := m.deploytimeDetector.RemovePolicy(policyID); err != nil {
		return err
	}
	if err := m.runtimeDetector.RemovePolicy(policyID); err != nil {
		return err
	}
	oldAlerts, err := m.alertManager.GetAlertsByPolicy(policyID)
	if err != nil {
		return err
	}
	return m.alertManager.AlertAndNotify(oldAlerts, nil)
}

// determineEnforcement returns the alert and its enforcement action to use from the input list (if any have enforcement).
func determineEnforcement(alerts []*v1.Alert) (alertID string, action v1.EnforcementAction) {
	for _, alert := range alerts {
		if alert.GetEnforcement().GetAction() == v1.EnforcementAction_SCALE_TO_ZERO_ENFORCEMENT {
			return alert.GetId(), v1.EnforcementAction_SCALE_TO_ZERO_ENFORCEMENT
		}

		if alert.GetEnforcement().GetAction() != v1.EnforcementAction_UNSET_ENFORCEMENT {
			alertID = alert.GetId()
			action = alert.GetEnforcement().GetAction()
		}
	}
	return
}

func uniqueDeploymentIDs(indicatorsToInfo map[string]indicatorWithInjector) []string {
	m := mapset.NewSet()
	for _, infoWithInjector := range indicatorsToInfo {
		deploymentID := infoWithInjector.indicator.GetDeploymentId()
		if deploymentID == "" {
			continue
		}
		m.Add(deploymentID)
	}
	return set.StringSliceFromSet(m)
}

func containersToKill(alerts []*v1.Alert, indicatorsToInfo map[string]indicatorWithInjector) map[string]indicatorWithInjector {
	containersSet := make(map[string]indicatorWithInjector)

	for _, alert := range alerts {
		if alert.GetEnforcement().GetAction() != v1.EnforcementAction_KILL_POD_ENFORCEMENT {
			continue
		}
		violations := alert.GetViolations()
		for _, v := range violations {
			for _, singleIndicator := range v.GetProcesses() {
				if infoWithInjector, ok := indicatorsToInfo[singleIndicator.GetId()]; ok {
					containersSet[infoWithInjector.indicator.GetSignal().GetContainerId()] = infoWithInjector
				}
			}
		}
	}

	return containersSet
}

func createEnforcementAction(deployment *v1.Deployment, containerID string) *v1.SensorEnforcement {
	containers := deployment.GetContainers()
	for _, container := range containers {
		for _, instance := range container.GetInstances() {
			if len(instance.GetInstanceId().GetId()) < 12 {
				continue
			}
			if containerID == instance.GetInstanceId().GetId()[:12] {
				resource := &v1.SensorEnforcement_ContainerInstance{
					ContainerInstance: &v1.ContainerInstanceEnforcement{
						ContainerInstanceId: instance.GetInstanceId().GetId(),
						PodId:               instance.GetContainingPodId(),
					},
				}
				return &v1.SensorEnforcement{
					Enforcement: v1.EnforcementAction_KILL_POD_ENFORCEMENT,
					Resource:    resource,
				}
			}
		}
	}
	return nil
}
