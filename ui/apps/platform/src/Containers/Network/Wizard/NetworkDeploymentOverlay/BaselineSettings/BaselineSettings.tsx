import React, { ReactElement } from 'react';

import { filterModes } from 'constants/networkFilterModes';
import useFetchNetworkBaselines from './useFetchNetworkBaselines';

import NetworkBaselines from '../NetworkBaselines';

function BaselineSettings({
    selectedDeployment,
    deploymentId,
    filterState,
    onNavigateToEntity,
}): ReactElement {
    const { data: networkBaselines, isLoading } = useFetchNetworkBaselines({
        selectedDeployment,
        deploymentId,
        filterState,
    });

    return (
        <NetworkBaselines
            header="Baseline Settings"
            isLoading={isLoading}
            networkBaselines={networkBaselines}
            deploymentId={deploymentId}
            filterState={filterModes}
            onNavigateToEntity={onNavigateToEntity}
        />
    );
}

export default BaselineSettings;
