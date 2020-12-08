/* eslint-disable react/jsx-no-bind */
import React from 'react';
import PropTypes from 'prop-types';

import { Tooltip, TooltipOverlay } from '@stackrox/ui-components';

import HealthStatus from './HealthStatus';
import HealthStatusNotApplicable from './HealthStatusNotApplicable';
import { findUpgradeState, formatSensorVersion, sensorUpgradeStyles } from '../cluster.helpers';

const trClassName = 'align-top leading-normal';
const thClassName = 'font-600 pl-0 pr-1 py-0 text-left';
const tdClassName = 'p-0 text-left';

const testId = 'sensorUpgrade';

/*
 * Sensor Upgrade cell
 * - in Clusters list might have an action (for example, Upgrade available or Retry upgrade)
 * - in Cluster side panel does not have an action (but might have an action in the future)
 */
const SensorUpgrade = ({ upgradeStatus, centralVersion, sensorVersion, isList, actionProps }) => {
    if (upgradeStatus) {
        const upgradeStateObject = findUpgradeState(upgradeStatus);
        if (upgradeStateObject) {
            const { displayValue, type, actionText } = upgradeStateObject;

            let displayElement = null;
            let actionElement = null;

            if (displayValue) {
                const { bgColor, fgColor } = sensorUpgradeStyles[type];
                displayElement = <span className={`${bgColor} ${fgColor}`}>{displayValue}</span>;
            }

            if (actionText) {
                const actionStyle = sensorUpgradeStyles.download;
                if (actionProps) {
                    const { clusterId, upgradeSingleCluster } = actionProps;
                    const onClick = (event) => {
                        event.stopPropagation(); // so click in row does not open side panel
                        upgradeSingleCluster(clusterId);
                    };

                    const { fgColor } = actionStyle;
                    actionElement = (
                        <button
                            type="button"
                            className={`bg-transparent leading-normal m-0 p-0 ${fgColor} underline`}
                            onClick={onClick}
                        >
                            {actionText}
                        </button>
                    );
                } else if (!displayElement) {
                    // Upgrade available is not an action in Cluster side panel,
                    // but it might become an action in the future.
                    const { bgColor, fgColor } = actionStyle;
                    displayElement = <span className={`${bgColor} ${fgColor}`}>{actionText}</span>;
                }
            }

            const upgradeElement = (
                <div data-testid={testId}>
                    {displayElement}
                    {displayElement && actionElement ? <br /> : null}
                    {actionElement}
                </div>
            );

            const { Icon, bgColor, fgColor } = sensorUpgradeStyles[type];

            // Use table instead of TooltipFieldValue to align version numbers.
            const versionNumbers = (
                <table>
                    <tbody>
                        <tr className={trClassName} key="sensorVersion">
                            <th className={thClassName} scope="row">
                                Sensor version:
                            </th>
                            <td className={tdClassName} data-testid="sensorVersion">
                                {sensorVersion && type === 'current' ? (
                                    <span className={`${bgColor} ${fgColor}`}>{sensorVersion}</span>
                                ) : (
                                    formatSensorVersion(sensorVersion)
                                )}
                            </td>
                        </tr>
                        <tr className={trClassName} key="centralVersion">
                            <th className={thClassName} scope="row">
                                Central version:
                            </th>
                            <td className={tdClassName} data-testid="centralVersion">
                                {type === 'download' ? (
                                    <span className={`${bgColor} ${fgColor}`}>
                                        {centralVersion}
                                    </span>
                                ) : (
                                    centralVersion
                                )}
                            </td>
                        </tr>
                    </tbody>
                </table>
            );

            const detailElement =
                (type === 'failure' || type === 'intervention') &&
                upgradeStatus?.mostRecentProcess?.progress?.upgradeStatusDetail ? (
                    <div className="mb-2" data-testid="upgradeStatusDetail">
                        {upgradeStatus.mostRecentProcess.progress.upgradeStatusDetail}
                    </div>
                ) : null;

            if (isList) {
                const overlayElement = detailElement ? (
                    <div>
                        {detailElement}
                        {versionNumbers}
                    </div>
                ) : (
                    versionNumbers
                );

                return (
                    <Tooltip content={<TooltipOverlay>{overlayElement}</TooltipOverlay>}>
                        <div>
                            <HealthStatus Icon={Icon} iconColor={fgColor}>
                                {upgradeElement}
                            </HealthStatus>
                        </div>
                    </Tooltip>
                );
            }

            return (
                <HealthStatus Icon={Icon} iconColor={fgColor}>
                    <div>
                        {upgradeElement}
                        {detailElement}
                        {versionNumbers}
                    </div>
                </HealthStatus>
            );
        }
    }

    return <HealthStatusNotApplicable testId={testId} />;
};

SensorUpgrade.propTypes = {
    // Document the properties accessed by the helper function:
    upgradeStatus: PropTypes.shape({
        upgradability: PropTypes.string,
        mostRecentProcess: PropTypes.shape({
            active: PropTypes.bool,
            progress: PropTypes.shape({
                upgradeState: PropTypes.string,
                upgradeStatusDetail: PropTypes.string,
            }),
            type: PropTypes.string,
        }),
    }),
    sensorVersion: PropTypes.string,
    centralVersion: PropTypes.string.isRequired,
    isList: PropTypes.bool.isRequired,
    actionProps: PropTypes.shape({
        clusterId: PropTypes.string.isRequired,
        upgradeSingleCluster: PropTypes.func.isRequired,
    }),
};

SensorUpgrade.defaultProps = {
    upgradeStatus: null,
    sensorVersion: '',
    actionProps: null,
};

export default SensorUpgrade;
