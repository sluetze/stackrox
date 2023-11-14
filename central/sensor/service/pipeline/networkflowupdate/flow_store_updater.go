package networkflowupdate

import (
	"context"

	networkBaselineManager "github.com/stackrox/rox/central/networkbaseline/manager"
	"github.com/stackrox/rox/central/networkgraph/flow/datastore"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/networkgraph"
	protobuf "google.golang.org/protobuf/types/known/timestamppb"
)

type flowPersister interface {
	update(ctx context.Context, newFlows []*storage.NetworkFlow, updateTS *protobuf.Timestamp) error
}

func newFlowPersister(flowStore datastore.FlowDataStore, networkBaselines networkBaselineManager.Manager) flowPersister {
	return &flowPersisterImpl{
		flowStore:                 flowStore,
		baselines:                 networkBaselines,
		seenBaselineRelevantFlows: make(map[networkgraph.NetworkConnIndicator]struct{}),
	}
}
