import { useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { gql, useQuery } from '@apollo/client';

import { selectors } from 'reducers';

type SelectorState = { selectedClusterId: string | null; selectedNamespaceFilters: string[] };
type SelectorResult = SelectorState;

const selector = createStructuredSelector<SelectorState, SelectorResult>({
    selectedClusterId: selectors.getSelectedNetworkClusterId,
    selectedNamespaceFilters: selectors.getSelectedNamespaceFilters,
});

// TODO Better reuse of this type elsewhere?
export type Namespace = {
    id: string;
    name: string;
};

type NamespaceMetadataResp = {
    id: string;
    results: {
        namespaces: {
            metadata: Namespace;
        }[];
    };
};

export const NAMESPACES_FOR_CLUSTER_QUERY = gql`
    query getClusterNamespaceNames($id: ID!) {
        results: cluster(id: $id) {
            id
            namespaces {
                metadata {
                    id
                    name
                }
            }
        }
    }
`;

function useNamespaceFilters() {
    const [availableNamespaceFilters, setAvailableNamespaceFilters] = useState<Namespace[]>([]);
    const { selectedClusterId, selectedNamespaceFilters } = useSelector<
        SelectorState,
        SelectorResult
    >(selector);
    // If the selectedClusterId has not been set yet, do not run the gql query
    const queryOptions = selectedClusterId
        ? { variables: { id: selectedClusterId } }
        : { skip: true };

    const { loading, error, data } = useQuery<NamespaceMetadataResp, { id: string }>(
        NAMESPACES_FOR_CLUSTER_QUERY,
        queryOptions
    );

    useEffect(() => {
        if (!data || !data.results) {
            return;
        }

        const namespaces = data.results.namespaces.map(({ metadata }) => metadata);

        setAvailableNamespaceFilters(namespaces);
    }, [data]);

    return {
        loading,
        error,
        availableNamespaceFilters,
        selectedNamespaceFilters,
    };
}

export default useNamespaceFilters;
