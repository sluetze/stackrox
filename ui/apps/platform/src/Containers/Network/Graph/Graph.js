import React, { Component } from 'react';
import { connect } from 'react-redux';
import { createSelector, createStructuredSelector } from 'reselect';
import PropTypes from 'prop-types';
import isEmpty from 'lodash/isEmpty';
import cloneDeep from 'lodash/cloneDeep';

import { selectors } from 'reducers';
import { actions as backendActions } from 'reducers/network/backend';
import { actions as graphActions } from 'reducers/network/graph';
import { actions as pageActions } from 'reducers/network/page';
import { actions as wizardActions } from 'reducers/network/wizard';
import { actions as deploymentActions } from 'reducers/deployments';
import NetworkGraph from 'Components/NetworkGraph';
import NoResultsMessage from 'Components/NoResultsMessage';
import { filterModes } from 'constants/networkFilterModes';
import { nodeTypes } from 'constants/networkGraph';
import entityTypes from 'constants/entityTypes';
import wizardStages from '../Wizard/wizardStages';
import Filters from './Overlays/Filters';
import Legend from './Overlays/Legend';

class Graph extends Component {
    static propTypes = {
        wizardOpen: PropTypes.bool.isRequired,
        openWizard: PropTypes.func.isRequired,
        closeWizard: PropTypes.func.isRequired,
        setWizardStage: PropTypes.func.isRequired,
        isSimulatorOn: PropTypes.bool.isRequired,

        networkNodeMap: PropTypes.shape({}).isRequired,
        networkEdgeMap: PropTypes.shape({}),

        networkFlowGraphUpdateKey: PropTypes.number.isRequired,
        fetchNetworkPolicies: PropTypes.func.isRequired,

        setSelectedNode: PropTypes.func.isRequired,
        setSelectedNamespace: PropTypes.func.isRequired,
        selectedNamespace: PropTypes.shape({
            id: PropTypes.string,
            deployments: PropTypes.arrayOf(PropTypes.shape({})),
        }),
        fetchDeployment: PropTypes.func.isRequired,
        clusters: PropTypes.arrayOf(PropTypes.object).isRequired,
        selectedClusterId: PropTypes.string,

        filterState: PropTypes.number.isRequired,
        isLoading: PropTypes.bool.isRequired,
        featureFlags: PropTypes.arrayOf(PropTypes.shape),
        setNetworkGraphRef: PropTypes.func.isRequired,
        setSelectedNodeInGraph: PropTypes.func,
        lastUpdatedTimestamp: PropTypes.instanceOf(Date),
    };

    static defaultProps = {
        networkEdgeMap: null,
        selectedClusterId: '',
        featureFlags: [],
        setSelectedNodeInGraph: null,
        lastUpdatedTimestamp: null,
        selectedNamespace: null,
    };

    shouldComponentUpdate(nextProps) {
        const {
            networkFlowGraphUpdateKey,
            filterState,
            isLoading,
            wizardOpen,
            networkEdgeMap,
            networkNodeMap,
            isSimulatorOn,
        } = this.props;
        return (
            !networkEdgeMap ||
            isEmpty(networkNodeMap) ||
            nextProps.networkFlowGraphUpdateKey !== networkFlowGraphUpdateKey ||
            nextProps.filterState !== filterState ||
            nextProps.isLoading !== isLoading ||
            nextProps.wizardOpen !== wizardOpen ||
            nextProps.isSimulatorOn !== isSimulatorOn
        );
    }

    onNamespaceClick = (namespace) => {
        if (this.props.isSimulatorOn) {
            return;
        }
        this.props.setSelectedNamespace(namespace);
        this.props.setWizardStage(wizardStages.namespaceDetails);
        this.props.openWizard();
    };

    // eslint-disable-next-line no-unused-vars
    onExternalEntitiesClick = () => {
        if (this.props.isSimulatorOn) {
            return;
        }
        this.props.setWizardStage(wizardStages.externalDetails);
        this.props.openWizard();
    };

    onNodeClick = (node) => {
        if (node?.type === entityTypes.CLUSTER || this.props.isSimulatorOn) {
            return;
        }
        this.props.setSelectedNode(node);
        this.props.fetchDeployment(node.deploymentId);
        this.props.fetchNetworkPolicies([...node.policyIds]);
        this.props.setWizardStage(wizardStages.details);
        this.props.openWizard();
    };

    renderGraph = (simulatorOn) => {
        const { networkNodeMap } = this.props;
        // If we have more than 1100 nodes, display a message instead of the graph.
        const nodeLimit = 1100;
        if (Object.keys(networkNodeMap).length > nodeLimit) {
            // hopefully a temporal solution
            return (
                <NoResultsMessage message="There are too many deployments to render on the graph. Please refine your search to a set of namespaces or deployments to display." />
            );
        }
        const {
            networkFlowGraphUpdateKey,
            networkEdgeMap,
            closeWizard,
            filterState,
            clusters,
            selectedClusterId,
            featureFlags,
            setNetworkGraphRef,
            setSelectedNamespace,
            setSelectedNodeInGraph,
            lastUpdatedTimestamp,
            selectedNamespace,
        } = this.props;

        const selectedClusterName =
            clusters.find((cluster) => cluster.id === selectedClusterId)?.name || 'Unknown cluster';

        const augmentedNetworkNodeMap =
            filterState === filterModes.all ? augmentCidrs(networkNodeMap) : networkNodeMap;

        return (
            <NetworkGraph
                updateKey={networkFlowGraphUpdateKey}
                networkEdgeMap={networkEdgeMap}
                networkNodeMap={augmentedNetworkNodeMap}
                onNodeClick={this.onNodeClick}
                onNamespaceClick={this.onNamespaceClick}
                onExternalEntitiesClick={this.onExternalEntitiesClick}
                onClickOutside={closeWizard}
                filterState={filterState}
                simulatorOn={simulatorOn}
                selectedClusterName={selectedClusterName}
                featureFlags={featureFlags}
                setNetworkGraphRef={setNetworkGraphRef}
                setSelectedNamespace={setSelectedNamespace}
                setSelectedNodeInGraph={setSelectedNodeInGraph}
                lastUpdatedTimestamp={lastUpdatedTimestamp}
                selectedNamespace={selectedNamespace}
                selectedClusterId={selectedClusterId}
            />
        );
    };

    render() {
        const { isSimulatorOn } = this.props;
        // Rendering.
        return (
            <div className="w-full h-full">
                {this.renderGraph(isSimulatorOn)}
                <Filters />
                <Legend />
            </div>
        );
    }
}

const getIsSimulatorOn = createSelector(
    [selectors.getNetworkWizardOpen, selectors.getNetworkWizardStage],
    (wizardOpen, wizardStage) =>
        wizardOpen &&
        (wizardStage === wizardStages.simulator || wizardStage === wizardStages.creator)
);

const mapStateToProps = createStructuredSelector({
    wizardOpen: selectors.getNetworkWizardOpen,
    filterState: selectors.getNetworkGraphFilterMode,
    isSimulatorOn: getIsSimulatorOn,
    networkNodeMap: selectors.getNetworkNodeMap,
    networkEdgeMap: selectors.getNetworkEdgeMap,
    networkFlowGraphUpdateKey: selectors.getNetworkFlowGraphUpdateKey,
    clusters: selectors.getClusters,
    selectedClusterId: selectors.getSelectedNetworkClusterId,
    isLoading: selectors.getNetworkGraphLoading,
    featureFlags: selectors.getFeatureFlags,
    networkWizardStage: selectors.getNetworkWizardStage,
    networkPolicyModification: selectors.getNetworkPolicyModification,
    lastUpdatedTimestamp: selectors.getLastUpdatedTimestamp,
    selectedNamespace: selectors.getSelectedNamespace,
});

const mapDispatchToProps = {
    setSelectedNode: graphActions.setSelectedNode,
    setSelectedNamespace: graphActions.setSelectedNamespace,
    fetchDeployment: deploymentActions.fetchDeployment.request,
    fetchNetworkPolicies: backendActions.fetchNetworkPolicies.request,
    openWizard: pageActions.openNetworkWizard,
    setWizardStage: wizardActions.setNetworkWizardStage,
    setNetworkGraphRef: graphActions.setNetworkGraphRef,
    setNetworkGraphLoading: graphActions.setNetworkGraphLoading,
    closeWizard: pageActions.closeNetworkWizard,
    setSelectedNodeInGraph: graphActions.setSelectedNode,
};

export default connect(mapStateToProps, mapDispatchToProps)(Graph);

function augmentCidrs(originalNodeMap) {
    const clonedMap = cloneDeep(originalNodeMap);

    Object.keys(clonedMap).forEach((id) => {
        if (
            clonedMap[id]?.active?.entity?.type === nodeTypes.CIDR_BLOCK &&
            !clonedMap[id]?.allowed
        ) {
            clonedMap[id].allowed = cloneDeep(originalNodeMap[id].active);
        }
    });
    return clonedMap;
}
