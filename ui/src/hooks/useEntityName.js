import { entityNameQueryMap } from 'utils/queryMap';
import getEntityName from 'utils/getEntityName';
import isGQLLoading from 'utils/gqlLoading';
import { useQuery } from '@apollo/client';

function useEntityName(entityType, entityId, skip) {
    // Header query
    const entityNameQuery = entityNameQueryMap[entityType];
    const nameQueryOptions = {
        options: {
            fetchPolicy: 'cache-first',
            skip,
        },
        variables: {
            id: entityId,
        },
    };
    const { loading, error, data } = useQuery(entityNameQuery, nameQueryOptions);

    let entityName;
    if (!isGQLLoading(loading, data)) {
        entityName = getEntityName(entityType, data);
    }

    return {
        loading,
        error,
        entityName,
    };
}

export default useEntityName;
