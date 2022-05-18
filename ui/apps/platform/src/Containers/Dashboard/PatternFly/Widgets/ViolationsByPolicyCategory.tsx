import React, { ReactNode, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { Card, Skeleton, Title } from '@patternfly/react-core';
import { Chart, ChartAxis, ChartStack, ChartBar, ChartTooltip } from '@patternfly/react-charts';

import { LinkableChartLabel } from 'Components/PatternFly/Charts/LinkableChartLabel';
import { AlertGroup } from 'services/AlertsService';
import { severityLabels } from 'messages/common';
import {
    navigateOnClickEvent,
    patternflySeverityTheme,
    defaultChartHeight as chartHeight,
    defaultChartBarWidth,
} from 'utils/chartUtils';
import { getQueryString } from 'utils/queryStringUtils';
import { violationsBasePath } from 'routePaths';
import useResizeObserver from 'hooks/useResizeObserver';
import useViolationCounts from '../hooks/useViolationCounts';
import WidgetErrorEmptyState from '../WidgetErrorEmptyState';

type CountsBySeverity = {
    Low: Record<string, number>;
    Medium: Record<string, number>;
    High: Record<string, number>;
    Critical: Record<string, number>;
};

function getCountsBySeverity(groups: AlertGroup[]): CountsBySeverity {
    const result = {
        Low: {},
        Medium: {},
        High: {},
        Critical: {},
    };

    groups.forEach(({ group, counts }) => {
        result.Low[group] = 0;
        result.Medium[group] = 0;
        result.High[group] = 0;
        result.Critical[group] = 0;

        counts.forEach(({ severity, count }) => {
            result[severityLabels[severity]][group] = parseInt(count, 10);
        });
    });

    return result;
}

function linkForViolationsCategory(category: string) {
    const queryString = getQueryString({
        s: { Category: category },
        sortOption: { field: 'Severity', direction: 'desc' },
    });
    return `${violationsBasePath}${queryString}`;
}

const height = `${chartHeight}px` as const;

function ViolationsByPolicyCategory() {
    const history = useHistory();
    const [widgetContainer, setWidgetContainer] = useState<HTMLDivElement | null>(null);
    const widgetContainerResizeEntry = useResizeObserver(widgetContainer);
    const { violationCounts, loading, error } = useViolationCounts('CATEGORY', ''); // TODO Implement query filtering

    const countsBySeverity = getCountsBySeverity(violationCounts);
    const bars = Object.entries(countsBySeverity).map(([severity, counts]) => {
        const data = Object.entries(counts).map(([group, count]) => ({
            name: severity,
            x: group,
            y: count,
            label: `${severity}: ${count}`,
        }));

        return (
            <ChartBar
                barWidth={defaultChartBarWidth}
                key={severity}
                data={data}
                labelComponent={<ChartTooltip constrainToVisibleArea />}
                events={[
                    navigateOnClickEvent(history, (props) => {
                        const category = props?.datum?.xName as string;
                        return linkForViolationsCategory(category);
                    }),
                ]}
            />
        );
    });

    let cardContent: ReactNode;

    if (error) {
        cardContent = (
            <WidgetErrorEmptyState height={height} title="Unable to load data">
                There was an error loading policy violation counts
            </WidgetErrorEmptyState>
        );
    } else if (loading) {
        cardContent = (
            <Skeleton height={height} screenreaderText="Loading Policy Violations By Category" />
        );
    } else {
        cardContent = (
            <div className="pf-u-px-md" ref={setWidgetContainer} style={{ height }}>
                <Chart
                    ariaDesc="Number of violation by policy category, grouped by severity"
                    ariaTitle="Policy Violations by Category"
                    domainPadding={{ x: [30, 25] }}
                    legendData={[
                        { name: 'Low' },
                        { name: 'Medium' },
                        { name: 'High' },
                        { name: 'Critical' },
                    ]}
                    legendPosition="bottom"
                    height={chartHeight}
                    width={widgetContainerResizeEntry?.contentRect.width} // Victory defaults to 450
                    padding={{
                        // TODO Auto-adjust padding based on screen size and/or max text length, if possible
                        left: 180, // left padding is dependent on the length of the text on the left axis
                        bottom: 75, // Adjusted to accommodate legend
                    }}
                    theme={patternflySeverityTheme}
                >
                    <ChartAxis
                        tickLabelComponent={
                            <LinkableChartLabel
                                linkWith={({ text }) => linkForViolationsCategory(String(text))}
                            />
                        }
                    />
                    <ChartAxis dependentAxis showGrid />
                    <ChartStack horizontal>{bars}</ChartStack>
                </Chart>
            </div>
        );
    }

    return (
        <Card>
            <Title headingLevel="h2" className="pf-u-p-md">
                Policy Violations by Category
            </Title>
            {cardContent}
        </Card>
    );
}

export default ViolationsByPolicyCategory;
