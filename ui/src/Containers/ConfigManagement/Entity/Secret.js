import React, { useContext } from 'react';
import PropTypes from 'prop-types';
import entityTypes from 'constants/entityTypes';
import dateTimeFormat from 'constants/dateTimeFormat';
import { format } from 'date-fns';

import Query from 'Components/ThrowingQuery';
import Loader from 'Components/Loader';
import PageNotFound from 'Components/PageNotFound';
import CollapsibleSection from 'Components/CollapsibleSection';
import RelatedEntity from 'Containers/ConfigManagement/Entity/widgets/RelatedEntity';
import RelatedEntityListCount from 'Containers/ConfigManagement/Entity/widgets/RelatedEntityListCount';
import Metadata from 'Containers/ConfigManagement/Entity/widgets/Metadata';
import CollapsibleRow from 'Components/CollapsibleRow';
import Widget from 'Components/Widget';
import gql from 'graphql-tag';
import searchContext from 'Containers/searchContext';
import { DEPLOYMENT_FRAGMENT } from 'queries/deployment';
import queryService from 'modules/queryService';
import { entityComponentPropTypes, entityComponentDefaultProps } from 'constants/entityPageProps';
import EntityList from '../List/EntityList';
import getSubListFromEntity from '../List/utilities/getSubListFromEntity';

const SecretDataMetadata = ({ metadata }) => {
    if (!metadata) return null;
    const { startDate, endDate, issuer = {}, sans = [], subject = {} } = metadata;
    const {
        commonName: issuerCommonName = 'N/A',
        names: issuerNames,
        organizationUnit = 'N/A'
    } = issuer;
    const { commonName: subjectCommonName = 'N/A', names: subjectNames } = subject;
    return (
        <div className="flex flex-row">
            <Widget
                header="Timeframe"
                className="m-4"
                bodyClassName="flex flex-col p-4 leading-normal"
            >
                <div>
                    <span className="font-700 mr-4">Start Date:</span>
                    <span>{startDate ? format(startDate, dateTimeFormat) : 'N/A'}</span>
                </div>
                <div>
                    <span className="font-700 mr-4">End Date:</span>
                    <span>{endDate ? format(endDate, dateTimeFormat) : 'N/A'}</span>
                </div>
            </Widget>
            <Widget
                header="Issuer"
                className="m-4"
                bodyClassName="flex flex-col p-4 leading-normal"
            >
                <div>
                    <span className="font-700 mr-4">Common Name:</span>
                    <span>{issuerCommonName}</span>
                </div>
                <div>
                    <span className="font-700 mr-4">Name(s):</span>
                    <span>{issuerNames ? issuerNames.join(', ') : 'None'}</span>
                </div>
                <div>
                    <span className="font-700 mr-4">Organization Unit:</span>
                    <span>{organizationUnit}</span>
                </div>
            </Widget>
            <Widget
                header="Subject"
                className="m-4"
                bodyClassName="flex flex-col p-4 leading-normal"
            >
                <div>
                    <span className="font-700 mr-4">Common Name:</span>
                    <span>{subjectCommonName}</span>
                </div>
                <div>
                    <span className="font-700 mr-4">Name(s):</span>
                    <span>{subjectNames ? subjectNames.join(', ') : 'None'}</span>
                </div>
            </Widget>
            {!!sans.length && (
                <Widget
                    header="SANS"
                    className="m-4"
                    bodyClassName="flex flex-col p-4 leading-normal"
                >
                    <div>
                        <span className="font-700 mr-4">SANS:</span>
                        <span>{sans.join(', ')}</span>
                    </div>
                </Widget>
            )}
        </div>
    );
};

SecretDataMetadata.propTypes = {
    metadata: PropTypes.shape()
};

SecretDataMetadata.defaultProps = {
    metadata: null
};

const SecretValues = ({ files, deploymentCount }) => {
    const filesWithoutImagePullSecrets = files.filter(
        // eslint-disable-next-line
        file => !file.metadata || (file.metadata && file.metadata.__typename !== 'ImagePullSecret')
    );
    const widgetHeader = `${
        filesWithoutImagePullSecrets.length
    } files across ${deploymentCount} deployment(s)`;
    const secretValues = filesWithoutImagePullSecrets.map((file, i) => {
        const { name, type, metadata } = file;
        const { algorithm } = metadata || {};
        const collapsibleRowHeader = (
            <div className="flex flex-1 w-full">
                <div className="flex flex-1">{name}</div>
                {type && (
                    <div className="border-l border-base-400 px-2 capitalize">
                        {type.replace(/_/g, ' ').toLowerCase()}
                    </div>
                )}
                {algorithm && <div className="border-l border-base-400 px-2">{algorithm}</div>}
            </div>
        );
        return (
            <CollapsibleRow key={i} header={collapsibleRowHeader} isCollapsible={!!metadata}>
                <SecretDataMetadata metadata={metadata} />
            </CollapsibleRow>
        );
    });
    return (
        <Widget header={widgetHeader} bodyClassName="flex flex-col">
            {secretValues}
        </Widget>
    );
};

SecretValues.propTypes = {
    files: PropTypes.arrayOf(PropTypes.shape).isRequired,
    deploymentCount: PropTypes.number.isRequired
};

const Secret = ({ id, entityListType, query }) => {
    const searchParam = useContext(searchContext);

    const variables = {
        id,
        query: queryService.objectToWhereClause({
            ...query[searchParam],
            'Lifecycle Stage': 'DEPLOY'
        })
    };

    const QUERY = gql`
        query getSecret($id: ID!, $query: String) {
            secret(id: $id) {
                id
                name
                createdAt
                files {
                    name
                    type
                    metadata {
                        __typename
                        ... on Cert {
                            endDate
                            startDate
                            algorithm
                            issuer {
                                commonName
                                names
                            }
                            subject {
                                commonName
                                names
                            }
                            sans
                        }
                        ... on ImagePullSecret {
                            registries {
                                name
                                username
                            }
                        }
                    }
                }
                namespace
                deployments(query: $query) {
                    ${entityListType === entityTypes.DEPLOYMENT ? '...deploymentFields' : 'id'}   
                }
                labels {
                    key
                    value
                }
                annotations {
                    key
                    value
                }
                clusterName
                clusterId
            }
        }
        ${entityListType === entityTypes.DEPLOYMENT ? DEPLOYMENT_FRAGMENT : ''}
    `;
    return (
        <Query query={QUERY} variables={variables}>
            {({ loading, data }) => {
                if (loading) return <Loader transparent />;
                if (!data || !data.secret)
                    return <PageNotFound resourceType={entityTypes.SECRET} />;
                const { secret } = data;
                if (!secret) return <PageNotFound resourceType={entityTypes.SECRET} />;

                if (entityListType) {
                    return (
                        <EntityList
                            entityListType={entityListType}
                            data={getSubListFromEntity(secret, entityListType)}
                            query={query}
                        />
                    );
                }

                const {
                    createdAt,
                    labels = [],
                    annotations = [],
                    deployments = [],
                    clusterName,
                    clusterId,
                    files
                } = secret;

                const metadataKeyValuePairs = [
                    {
                        key: 'Created',
                        value: createdAt ? format(createdAt, dateTimeFormat) : 'N/A'
                    }
                ];

                return (
                    <div className="w-full" id="capture-dashboard-stretch">
                        <CollapsibleSection title="Secret Details">
                            <div className="flex mb-4 flex-wrap pdf-page">
                                <Metadata
                                    className="mx-4 bg-base-100 h-48 mb-4"
                                    keyValuePairs={metadataKeyValuePairs}
                                    labels={labels}
                                    annotations={annotations}
                                />
                                <RelatedEntity
                                    className="mx-4 min-w-48 h-48 mb-4"
                                    entityType={entityTypes.CLUSTER}
                                    name="Cluster"
                                    value={clusterName}
                                    entityId={clusterId}
                                />
                                <RelatedEntityListCount
                                    className="mx-4 min-w-48 h-48 mb-4"
                                    name="Deployments"
                                    value={deployments.length}
                                    entityType={entityTypes.DEPLOYMENT}
                                />
                            </div>
                        </CollapsibleSection>
                        <CollapsibleSection title="Secret Values">
                            <div className="flex pdf-page pdf-stretch mb-4 ml-4 mr-4">
                                <SecretValues files={files} deploymentCount={deployments.length} />
                            </div>
                        </CollapsibleSection>
                    </div>
                );
            }}
        </Query>
    );
};

Secret.propTypes = entityComponentPropTypes;
Secret.defaultProps = entityComponentDefaultProps;

export default Secret;
