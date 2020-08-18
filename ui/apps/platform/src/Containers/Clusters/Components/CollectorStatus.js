import PropTypes from 'prop-types';
import React from 'react';

import DetailedTooltipOverlay from 'Components/DetailedTooltipOverlay';
import Tooltip from 'Components/Tooltip';
import TooltipOverlay from 'Components/TooltipOverlay';
import { healthStatusLabels } from 'messages/common';
import { getDistanceStrictAsPhrase } from 'utils/dateUtils';

import HealthStatus from './HealthStatus';
import HealthStatusNotApplicable from './HealthStatusNotApplicable';
import {
    delayedCollectorStatusStyle,
    healthStatusStyles,
    isDelayedSensorHealthStatus,
} from '../cluster.helpers';

const trClassName = 'align-bottom leading-normal'; // align-bottom in case heading text wraps
const thClassName = 'font-600 pl-0 pr-1 py-0 text-left';
const tdClassName = 'p-0 text-right';

/*
 * Collector Status in Clusters list if `isList={true}` or Cluster side panel if `isList={false}`
 *
 * Caller is responsible for optional chaining in case healthStatus is null.
 */
const CollectorStatus = ({
    collectorHealthStatus,
    collectorHealthInfo,
    healthInfoComplete,
    sensorHealthStatus,
    lastContact,
    currentDatetime,
    isList,
}) => {
    if (collectorHealthStatus) {
        const { Icon, bgColor, fgColor } =
            lastContact && isDelayedSensorHealthStatus(sensorHealthStatus)
                ? delayedCollectorStatusStyle
                : healthStatusStyles[collectorHealthStatus];
        const labelElement = (
            <span className={`${bgColor} ${fgColor}`}>
                {healthStatusLabels[collectorHealthStatus]}
            </span>
        );

        // In rare case that the block does not fit in a narrow column,
        // the space and "whitespace-no-wrap" cause time phrase to wrap as a unit.
        // Order arguments according to date-fns@2 convention:
        // If lastContact <= currentDateTime: X units ago
        const statusElement =
            lastContact && isDelayedSensorHealthStatus(sensorHealthStatus) ? (
                <div>
                    {labelElement}{' '}
                    <span className="whitespace-no-wrap">
                        {getDistanceStrictAsPhrase(lastContact, currentDatetime)}
                    </span>
                </div>
            ) : (
                <div>{labelElement}</div>
            );

        if (collectorHealthInfo) {
            const { totalReadyPods, totalDesiredPods, totalRegisteredNodes } = collectorHealthInfo;
            const totalsElement = (
                <table>
                    <tbody>
                        <tr className={trClassName} key="totalReadyPods">
                            <th className={thClassName} scope="row">
                                Collector pods ready:
                            </th>
                            <td className={tdClassName}>
                                <span className={`${bgColor} ${fgColor}`}>{totalReadyPods}</span>
                            </td>
                        </tr>
                        <tr className={trClassName} key="totalDesiredPods">
                            <th className={thClassName} scope="row">
                                Collector pods expected:
                            </th>
                            <td className={tdClassName}>
                                <span className={`${bgColor} ${fgColor}`}>{totalDesiredPods}</span>
                            </td>
                        </tr>
                        <tr className={trClassName} key="totalRegisteredNodes">
                            <th className={thClassName} scope="row">
                                Registered nodes in cluster:
                            </th>
                            <td className={tdClassName}>{totalRegisteredNodes}</td>
                        </tr>
                    </tbody>
                </table>
            );

            const infoElement = healthInfoComplete ? (
                totalsElement
            ) : (
                <div>
                    {totalsElement}
                    <div>
                        <strong>Upgrade Sensor</strong> to get complete Collector health information
                    </div>
                </div>
            );

            return isList ? (
                <Tooltip
                    content={
                        <DetailedTooltipOverlay
                            title="Collector Health Information"
                            body={infoElement}
                        />
                    }
                >
                    <div>
                        <HealthStatus Icon={Icon} iconColor={fgColor}>
                            {statusElement}
                        </HealthStatus>
                    </div>
                </Tooltip>
            ) : (
                <HealthStatus Icon={Icon} iconColor={fgColor}>
                    <div>
                        {statusElement}
                        {infoElement}
                    </div>
                </HealthStatus>
            );
        }

        if (collectorHealthStatus === 'UNAVAILABLE') {
            const reasonUnavailable = (
                <div>
                    <strong>Upgrade Sensor</strong> to get Collector health information
                </div>
            );

            return isList ? (
                <Tooltip content={<TooltipOverlay>{reasonUnavailable}</TooltipOverlay>}>
                    <div>
                        <HealthStatus Icon={Icon} iconColor={fgColor}>
                            {labelElement}
                        </HealthStatus>
                    </div>
                </Tooltip>
            ) : (
                <HealthStatus Icon={Icon} iconColor={fgColor}>
                    <div>
                        {labelElement}
                        {reasonUnavailable}
                    </div>
                </HealthStatus>
            );
        }

        // UNINITIALIZED
        return (
            <HealthStatus Icon={Icon} iconColor={fgColor}>
                <div>{labelElement}</div>
            </HealthStatus>
        );
    }

    return <HealthStatusNotApplicable />;
};

CollectorStatus.propTypes = {
    collectorHealthStatus: PropTypes.oneOf([
        'UNINITIALIZED',
        'UNAVAILABLE',
        'UNHEALTHY',
        'DEGRADED',
        'HEALTHY',
    ]),
    collectorHealthInfo: PropTypes.shape({
        totalDesiredPods: PropTypes.number.isRequired,
        totalReadyPods: PropTypes.number.isRequired,
        totalRegisteredNodes: PropTypes.number.isRequired,
    }),
    healthInfoComplete: PropTypes.bool,
    sensorHealthStatus: PropTypes.oneOf(['UNINITIALIZED', 'UNHEALTHY', 'DEGRADED', 'HEALTHY']),
    lastContact: PropTypes.string, // ISO 8601
    currentDatetime: PropTypes.instanceOf(Date).isRequired,
    isList: PropTypes.bool.isRequired,
};

CollectorStatus.defaultProps = {
    collectorHealthStatus: null,
    collectorHealthInfo: null,
    healthInfoComplete: false,
    sensorHealthStatus: null,
    lastContact: null,
};

export default CollectorStatus;
