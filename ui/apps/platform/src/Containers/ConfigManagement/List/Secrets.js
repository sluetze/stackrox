import React from 'react';
import uniq from 'lodash/uniq';
import { format } from 'date-fns';
import pluralize from 'pluralize';

import {
    defaultHeaderClassName,
    defaultColumnClassName,
    nonSortableHeaderClassName,
} from 'Components/Table';
import dateTimeFormat from 'constants/dateTimeFormat';
import entityTypes from 'constants/entityTypes';
import { entityListPropTypes, entityListDefaultprops } from 'constants/entityPageProps';
import { SECRETS_QUERY } from 'queries/secret';
import { secretSortFields } from 'constants/sortFields';
import queryService from 'utils/queryService';
import URLService from 'utils/URLService';
import List from './List';
import TableCellLink from './Link';

const secretTypeEnumMapping = {
    UNDETERMINED: 'Undetermined',
    PUBLIC_CERTIFICATE: 'Public Certificate',
    CERTIFICATE_REQUEST: 'Certificate Request',
    PRIVACY_ENHANCED_MESSAGE: 'Privacy Enhanced Message',
    OPENSSH_PRIVATE_KEY: 'OpenSSH Private Key',
    PGP_PRIVATE_KEY: 'PGP Private Key',
    EC_PRIVATE_KEY: 'EC Private Key',
    RSA_PRIVATE_KEY: 'RSA Private Key',
    DSA_PRIVATE_KEY: 'DSA Private Key',
    CERT_PRIVATE_KEY: 'Certificate Private Key',
    ENCRYPTED_PRIVATE_KEY: 'Encrypted Private Key',
    IMAGE_PULL_SECRET: 'Image Pull Secret',
};

export const defaultSecretSort = [
    {
        id: secretSortFields.SECRET,
        desc: false,
    },
];

const buildTableColumns = (match, location, entityContext) => {
    const tableColumns = [
        {
            Header: 'Id',
            headerClassName: 'hidden',
            className: 'hidden',
            accessor: 'id',
        },
        {
            Header: `Secret`,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            accessor: 'name',
            id: secretSortFields.SECRET,
            sortField: secretSortFields.SECRET,
        },
        {
            Header: `Created`,
            headerClassName: `w-1/8 ${defaultHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            Cell: ({ original }) => {
                const { createdAt } = original;
                return format(createdAt, dateTimeFormat);
            },
            accessor: 'createdAt',
            id: secretSortFields.CREATED,
            sortField: secretSortFields.CREATED,
        },
        {
            Header: `Types`,
            headerClassName: `w-1/8 ${nonSortableHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            accessor: 'files',
            // eslint-disable-next-line
            Cell: ({ original }) => {
                const { files } = original;
                if (!files.length) {
                    return 'No Types';
                }
                return (
                    <span>
                        {uniq(files.map((file) => secretTypeEnumMapping[file.type])).join(', ')}
                    </span>
                );
            },
            sortable: false,
        },
        entityContext && entityContext[entityTypes.CLUSTER]
            ? null
            : {
                  Header: `Cluster`,
                  headerClassName: `w-1/8 ${defaultHeaderClassName}`,
                  className: `w-1/8 ${defaultColumnClassName}`,
                  accessor: 'clusterName',
                  // eslint-disable-next-line
                  Cell: ({ original, pdf }) => {
                      const { clusterName, clusterId, id } = original;
                      const url = URLService.getURL(match, location)
                          .push(id)
                          .push(entityTypes.CLUSTER, clusterId)
                          .url();
                      return <TableCellLink pdf={pdf} url={url} text={clusterName} />;
                  },
                  id: secretSortFields.CLUSTER,
                  sortField: secretSortFields.CLUSTER,
              },
        {
            Header: `Deployments`,
            headerClassName: `w-1/8 ${nonSortableHeaderClassName}`,
            className: `w-1/8 ${defaultColumnClassName}`,
            accessor: 'deployments',
            // eslint-disable-next-line
            Cell: ({ original, pdf }) => {
                const { deploymentCount, id } = original;
                if (!deploymentCount) {
                    return 'No Deployments';
                }
                const url = URLService.getURL(match, location)
                    .push(id)
                    .push(entityTypes.DEPLOYMENT)
                    .url();
                const text = `${deploymentCount} ${pluralize('Deployment', deploymentCount)}`;
                return <TableCellLink dataTestId="deployment" pdf={pdf} url={url} text={text} />;
            },
            sortable: false,
        },
    ];
    return tableColumns.filter((col) => col);
};

const createTableRows = (data) => {
    return data.secrets;
};

const Secrets = ({
    match,
    location,
    className,
    selectedRowId,
    onRowClick,
    query,
    data,
    totalResults,
    entityContext,
}) => {
    const autoFocusSearchInput = !selectedRowId;
    const tableColumns = buildTableColumns(match, location, entityContext);
    const queryText = queryService.objectToWhereClause(query);
    const variables = queryText ? { query: queryText } : null;
    return (
        <List
            className={className}
            query={SECRETS_QUERY}
            variables={variables}
            entityType={entityTypes.SECRET}
            tableColumns={tableColumns}
            createTableRows={createTableRows}
            onRowClick={onRowClick}
            selectedRowId={selectedRowId}
            idAttribute="id"
            defaultSorted={defaultSecretSort}
            data={data}
            totalResults={totalResults}
            autoFocusSearchInput={autoFocusSearchInput}
        />
    );
};
Secrets.propTypes = entityListPropTypes;
Secrets.defaultProps = entityListDefaultprops;

export default Secrets;
