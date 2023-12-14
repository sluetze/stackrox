package networkflowupdate

import (
	"context"

	"github.com/gogo/protobuf/types"
	networkBaselineManager "github.com/stackrox/rox/central/networkbaseline/manager"
	entityDataStore "github.com/stackrox/rox/central/networkgraph/entity/datastore"
	flowDataStore "github.com/stackrox/rox/central/networkgraph/flow/datastore"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/networkgraph"
	"github.com/stackrox/rox/pkg/timestamp"
)

type flowPersisterImpl struct {
	seenBaselineRelevantFlows map[networkgraph.NetworkConnIndicator]struct{}

	baselines       networkBaselineManager.Manager
	flowStore       flowDataStore.FlowDataStore
	firstUpdateSeen bool
}

// update updates the FlowStore with the given network flow updates.
func (s *flowPersisterImpl) update(ctx context.Context, newFlows []*storage.NetworkFlow, updateTS *types.Timestamp) error {
	now := timestamp.Now()
	updateMicroTS := timestamp.FromProtobuf(updateTS)

	flowsByIndicator := getFlowsByIndicator(newFlows, updateMicroTS, now)
	if err := s.baselines.ProcessFlowUpdate(flowsByIndicator); err != nil {
		return err
	}

	// Add existing unterminated flows from the store if this is the first run this time round.
	if !s.firstUpdateSeen {
		if err := s.markExistingFlowsAsTerminatedIfNotSeen(ctx, flowsByIndicator); err != nil {
			return err
		}
		s.firstUpdateSeen = true
	}

	// Sensor may have forwarded unknown NetworkEntities that we want to learn
	for _, newFlow := range newFlows {
		err := s.learnExternalEntity(ctx, newFlow.GetProps().DstEntity)
		if err != nil {
			return err
		}
		err = s.learnExternalEntity(ctx, newFlow.GetProps().SrcEntity)
		if err != nil {
			return err
		}
	}

	return s.flowStore.UpsertFlows(ctx, convertToFlows(flowsByIndicator), now)
}

func (s *flowPersisterImpl) markExistingFlowsAsTerminatedIfNotSeen(ctx context.Context, currentFlows map[networkgraph.NetworkConnIndicator]timestamp.MicroTS) error {
	existingFlows, lastUpdateTS, err := s.flowStore.GetAllFlows(ctx, nil)
	if err != nil {
		return err
	}

	closeTS := timestamp.FromProtobuf(lastUpdateTS)
	if closeTS == 0 {
		closeTS = timestamp.Now()
	}

	// If there are flows in the store that are not terminated, and which are NOT present in the currentFlows,
	// then we need to mark them as terminated, with a timestamp of closeTS.
	for _, flow := range existingFlows {
		// An empty last seen timestamp means the flow had not been terminated
		// the last time we wrote it.
		if flow.GetLastSeenTimestamp() == nil {
			indicator := networkgraph.GetNetworkConnIndicator(flow)
			if _, stillExists := currentFlows[indicator]; !stillExists {
				currentFlows[indicator] = closeTS
			}
		}
	}
	return nil
}

func getFlowsByIndicator(newFlows []*storage.NetworkFlow, updateTS, now timestamp.MicroTS) map[networkgraph.NetworkConnIndicator]timestamp.MicroTS {
	out := make(map[networkgraph.NetworkConnIndicator]timestamp.MicroTS, len(newFlows))
	tsOffset := now - updateTS
	for _, newFlow := range newFlows {
		t := timestamp.FromProtobuf(newFlow.LastSeenTimestamp)
		if newFlow.LastSeenTimestamp != nil {
			t = t + tsOffset
		}
		out[networkgraph.GetNetworkConnIndicator(newFlow)] = t
	}
	return out
}

func convertToFlows(updatedFlows map[networkgraph.NetworkConnIndicator]timestamp.MicroTS) []*storage.NetworkFlow {
	flowsToBeUpserted := make([]*storage.NetworkFlow, 0, len(updatedFlows))
	for indicator, ts := range updatedFlows {
		toBeUpserted := &storage.NetworkFlow{
			Props:             indicator.ToNetworkFlowPropertiesProto(),
			LastSeenTimestamp: convertTS(ts),
		}
		flowsToBeUpserted = append(flowsToBeUpserted, toBeUpserted)
	}
	return flowsToBeUpserted
}

func convertTS(ts timestamp.MicroTS) *types.Timestamp {
	if ts == 0 {
		return nil
	}
	return ts.GogoProtobuf()
}

func (s *flowPersisterImpl) learnExternalEntity(ctx context.Context, entityInfo *storage.NetworkEntityInfo) error {
	if !entityInfo.GetExternalSource().GetLearned() {
		return nil
	}

	entity := &storage.NetworkEntity{
		Info: entityInfo,
		// Scope.ClusterId defaults to "", which is the default cluster
	}

	return entityDataStore.Singleton().UpdateExternalNetworkEntity(ctx, entity, true)
}
