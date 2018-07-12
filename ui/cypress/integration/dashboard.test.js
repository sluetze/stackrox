import { url as dashboardUrl, selectors } from './constants/DashboardPage';

import {
    url as complianceUrl,
    selectors as compliancePageSelectors
} from './constants/CompliancePage';
import { url as violationsUrl } from './constants/ViolationsPage';
import * as api from './constants/apiEndpoints';

describe('Dashboard page', () => {
    it('should select item in nav bar', () => {
        cy.visit(dashboardUrl);
        cy.get(selectors.navLink).should('have.class', 'bg-primary-600');
    });

    it('should display benchmarks data', () => {
        cy.server();

        cy.fixture('benchmarks/summary.json').as('benchmarksSummary');
        cy
            .route('GET', api.benchmarks.summary, '@benchmarksSummary')
            .as('benchmarksSummaryByCluster');

        cy.visit(dashboardUrl);
        cy.wait('@benchmarksSummaryByCluster');

        cy
            .get(selectors.sectionHeaders.benchmarks)
            .next()
            .children()
            .as('benchmarkSummaries');
        cy
            .get('@benchmarkSummaries')
            .find('a')
            .first()
            .should('have.text', 'CIS Docker v1.1.0 Benchmark');

        cy
            .get('@benchmarkSummaries')
            .find('a')
            .next()
            .children()
            .spread((pass, warn, info, note) => {
                expect(pass.getAttribute('style')).to.have.string('width: 30%');
                expect(warn.getAttribute('style')).to.have.string('width: 31%');
                expect(info.getAttribute('style')).to.have.string('width: 9%');
                expect(note.getAttribute('style')).to.have.string('width: 32%');
            });
        cy
            .get('@benchmarkSummaries')
            .find('a')
            .first()
            .click();
        cy.location().should(location => {
            expect(location.pathname).to.eq(
                `${complianceUrl}/422642b9-1e4e-47a5-a739-e4fb39230822`
            );
        });

        cy.visit(dashboardUrl);
        cy.get(selectors.slick.dashboardBenchmarks.nextButton).click();
        cy.get(selectors.slick.dashboardBenchmarks.currentSlide).contains('No Benchmark Results');
    });

    it('should display environment risk tiles', () => {
        cy.server();
        cy.fixture('alerts/countsByCluster-single.json').as('countsByCluster');
        cy.route('GET', api.alerts.countsByCluster, '@countsByCluster').as('alertsByCluster');

        cy.visit(dashboardUrl);
        cy.wait('@alertsByCluster');

        cy
            .get(selectors.sectionHeaders.environmentRisk)
            .next('div')
            .children()
            .as('riskTiles');

        cy.get('@riskTiles').spread((aCritical, aHigh, aMedium, aLow) => {
            cy.wrap(aLow).should('have.text', '2Low');
            cy.wrap(aMedium).should('have.text', '1Medium');
            cy.wrap(aHigh).should('have.text', '0High');
            cy.wrap(aCritical).should('have.text', '0Critical');
        });
    });

    it('should not navigate to the violations page when clicking the critical severity risk tile', () => {
        cy
            .get(selectors.sectionHeaders.environmentRisk)
            .next('div')
            .children()
            .as('riskTiles');

        cy
            .get('@riskTiles')
            .first()
            .click();
        cy.location().should(location => {
            expect(location.pathname).to.eq(dashboardUrl);
        });
    });

    it('should navigate to violations page when clicking the low severity tile', () => {
        cy
            .get(selectors.sectionHeaders.environmentRisk)
            .next('div')
            .children()
            .as('riskTiles');

        cy
            .get('@riskTiles')
            .last()
            .click();
        cy.location().should(location => {
            expect(location.pathname).to.eq(violationsUrl);
            expect(location.search).to.eq('?severity=LOW_SEVERITY');
        });
    });

    it('should display violations by cluster chart for single cluster', () => {
        cy.server();
        cy.fixture('alerts/countsByCluster-single.json').as('countsByCluster');
        cy.route('GET', api.alerts.countsByCluster, '@countsByCluster').as('alertsByCluster');

        cy.visit(dashboardUrl);
        cy.wait('@alertsByCluster');

        cy
            .get(selectors.sectionHeaders.violationsByClusters)
            .next()
            .as('chart');

        cy.get('@chart').within(() => {
            cy.get(selectors.chart.xAxis).should('contain', 'Swarm Cluster 1');
            cy.get(selectors.chart.grid).spread(grid => {
                // from alerts fixture : low = 2, medium = 1, therefore medium's height should be twice less
                const { height } = grid.getBBox();
                cy.get(selectors.chart.lowSeverityBar).should('have.attr', 'height', `${height}`);
                cy
                    .get(selectors.chart.medSeverityBar)
                    .should('have.attr', 'height', `${height / 2}`);
            });
        });

        // TODO: validate clicking on any bar (for some reason '.click()' doesn't simply work for D3 chart)
    });

    it('should display violations by cluster chart for two clusters', () => {
        cy.server();
        cy.fixture('alerts/countsByCluster-couple.json').as('countsByCluster');
        cy.route('GET', api.alerts.countsByCluster, '@countsByCluster').as('alertsByCluster');

        cy.visit(dashboardUrl);
        cy.wait('@alertsByCluster');

        cy
            .get(selectors.sectionHeaders.violationsByClusters)
            .next()
            .find(selectors.chart.xAxis)
            .should('contain', 'Kubernetes Cluster 1');
    });

    it('should display events by time charts', () => {
        cy.server();
        cy.fixture('alerts/alertsByTimeseries.json').as('alertsByTimeseries');
        cy.route('GET', api.dashboard.timeseries, '@alertsByTimeseries').as('alertsByTimeseries');
        cy.visit(dashboardUrl);
        cy.wait('@alertsByTimeseries');
        cy
            .get(selectors.sectionHeaders.eventsByTime)
            .next()
            .find(selectors.timeseries);
    });

    it('should display violations category chart', () => {
        cy.server();
        cy.fixture('alerts/countsByCategory.json').as('countsByCategory');
        cy.route('GET', api.alerts.countsByCategory, '@countsByCategory').as('alertsByCategory');

        cy.visit(dashboardUrl);
        cy.wait('@alertsByCategory');

        cy
            .get(selectors.sectionHeaders.containerConfiguration)
            .next()
            .as('chart');
        cy
            .get('@chart')
            .find(selectors.chart.legendItem)
            .should('have.text', 'Medium');

        // TODO: validate clicking on any sector (for some reason '.click()' isn't stable for D3 chart)
    });

    it('should display top risky deployments', () => {
        cy.server();
        cy.fixture('risks/riskyDeployments.json').as('riskyDeployments');
        cy.route('GET', api.risks.riskyDeployments, '@riskyDeployments').as('riskyDeployments');

        cy.visit(dashboardUrl);
        cy.wait('@riskyDeployments');

        cy
            .get(selectors.sectionHeaders.topRiskyDeployments)
            .next()
            .as('list');

        // Should only display the top 5 risky deployments
        cy
            .get('@list')
            .find('li')
            .should('have.length', 5);

        cy.get(selectors.buttons.more).click();
        cy.url().should('match', /\/main\/risk/);

        // TODO: validate clicking on any sector (for some reason '.click()' isn't stable for D3 chart)
    });

    it('should display a search input with only the cluster search modifier', () => {
        cy.visit(dashboardUrl);
        cy.get(selectors.searchInput).type('Cluster:{enter}', { force: true });
        cy.get(selectors.searchInput).type('remote{enter}', { force: true });
    });

    it('should show the proper empty states', () => {
        cy.server();
        cy.route('GET', api.alerts.countsByCategory, { groups: [] }).as('alertsByCategory');
        cy.route('GET', api.alerts.countsByCluster, { groups: [] }).as('alertsByCluster');

        cy.visit(dashboardUrl);
        cy.wait('@alertsByCategory');
        cy.wait('@alertsByCluster');

        cy.get(selectors.sectionHeaders.containerConfiguration).should('not.exist');
        cy.get(selectors.sectionHeaders.imageAssurance).should('not.exist');

        cy
            .get(selectors.sectionHeaders.violationsByClusters)
            .next()
            .should('have.text', 'No Clusters Available. Please refine search');
    });
    it('validate scans for multi clusters', () => {
        cy.server();
        cy.route('GET', '/v1/clusters').as('clusters');
        cy.visit(dashboardUrl);
        cy
            .get(compliancePageSelectors.leftNavigation)
            .contains('Compliance')
            .click();
        cy.wait('@clusters').then(cluster => {
            const { clusters } = cluster.response.body;
            clusters.forEach(clust => {
                cy.route('GET', '/v1/benchmarks/scans**').as('scans');
                cy.visit(`/main/compliance/${clust.id}`);
                cy.get('button:contains("Scan now")').click();
                cy.wait('@scans');
                cy.visit(dashboardUrl);
                cy
                    .get(selectors.slick.dashboardBenchmarks.slickSlideHeader)
                    .should('contain', clust.name);
            });
        });
    });
});
