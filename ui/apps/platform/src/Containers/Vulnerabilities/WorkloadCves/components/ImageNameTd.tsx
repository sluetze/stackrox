import React from 'react';
import { Link } from 'react-router-dom';
import { Flex, Truncate } from '@patternfly/react-core';

import { getEntityPagePath } from '../searchUtils';
import useVulnerabilityState from '../hooks/useVulnerabilityState';

export type ImageNameTdProps = {
    name: {
        remote: string;
        registry: string;
        tag: string;
    };
    id: string;
    children?: React.ReactNode;
};

function ImageNameTd({ name, id, children }: ImageNameTdProps) {
    const vulnerabilityState = useVulnerabilityState();
    return (
        <Flex direction={{ default: 'column' }} spaceItems={{ default: 'spaceItemsNone' }}>
            <Link to={getEntityPagePath('Image', id, vulnerabilityState)}>
                <Truncate position="middle" content={`${name.remote}:${name.tag}`} />
            </Link>{' '}
            <span className="pf-u-color-200 pf-u-font-size-sm">in {name.registry}</span>
            <div>{children}</div>
        </Flex>
    );
}

export default ImageNameTd;
