/* eslint-disable react/prop-types */
import React from 'react';
import PropTypes from 'prop-types';
import { useQuery } from 'react-apollo';

import PageNotFound from 'Components/PageNotFound';
import Loader from 'Components/Loader';
import { useTheme } from 'Containers/ThemeProvider';
import queryService from 'modules/queryService';

export const entityGridContainerBaseClassName =
    'mx-4 grid-dense grid-auto-fit grid grid-gap-6 mb-4 xxxl:grid-gap-8';

// to separate out column number related classes from the rest of the grid classes for easy column customization (see policyOverview component)
export const entityGridContainerClassName = `${entityGridContainerBaseClassName} grid-columns-1 lg:grid-columns-2 xl:grid-columns-3`;

const WorkflowEntityPage = ({
    ListComponent,
    OverviewComponent,
    entityType,
    entityId,
    entityListType,
    useCase,
    getListQuery,
    overviewQuery,
    queryOptions,
    entityContext,
    search,
    sort,
    page
}) => {
    const { isDarkMode } = useTheme();
    let query = overviewQuery;
    let fieldName;
    if (entityListType) {
        const { listFieldName, fragmentName, fragment } = queryService.getFragmentInfo(
            entityType,
            entityListType,
            useCase
        );
        fieldName = listFieldName;
        query = getListQuery(listFieldName, fragmentName, fragment);
    }

    // TODO: remove this hack after we are able to search for k8s vulns
    if (
        queryOptions &&
        queryOptions.variables &&
        queryOptions.variables.query &&
        queryOptions.variables.query.includes('K8S_VULNERABILITY')
    ) {
        // eslint-disable-next-line no-param-reassign
        queryOptions.variables.query = queryOptions.variables.query.replace(
            /\+?Vulnerability Type:K8S_VULNERABILITY\+?/,
            ''
        );
    }

    const { loading, data } = useQuery(query, queryOptions);
    if (loading) return <Loader transparent />;
    if (!data || !data.result) return <PageNotFound resourceType={entityType} />;
    const { result } = data;

    const listData = entityListType ? result[fieldName] : null;
    return entityListType ? (
        <ListComponent
            entityListType={entityListType}
            data={listData}
            search={search}
            sort={sort}
            page={page}
            entityContext={{ ...entityContext, [entityType]: entityId }}
        />
    ) : (
        <div
            className={`w-full flex ${
                !isDarkMode && !entityListType ? 'bg-side-panel-wave min-h-full' : 'h-full'
            }`}
        >
            <div className="w-full min-h-full" id="capture-widgets">
                <OverviewComponent data={result} entityContext={entityContext} />
            </div>
        </div>
    );
};

WorkflowEntityPage.propTypes = {
    ListComponent: PropTypes.func.isRequired,
    OverviewComponent: PropTypes.func.isRequired,
    entityType: PropTypes.string.isRequired,
    entityId: PropTypes.string.isRequired,
    entityListType: PropTypes.string,
    useCase: PropTypes.string.isRequired,
    getListQuery: PropTypes.func.isRequired,
    overviewQuery: PropTypes.shape({}).isRequired,
    queryOptions: PropTypes.shape({}),
    entityContext: PropTypes.shape({}),
    search: PropTypes.shape({}),
    sort: PropTypes.arrayOf(PropTypes.string),
    page: PropTypes.number
};

WorkflowEntityPage.defaultProps = {
    entityListType: null,
    queryOptions: null,
    entityContext: {},
    search: null,
    sort: null,
    page: 1
};

export default WorkflowEntityPage;
