import React from 'react';

import WorkloadTableToolbar from './WorkloadTableToolbar';

function setup() {
    cy.mount(<WorkloadTableToolbar />);
}

const searchOptionsDropdown = () => cy.findByLabelText('search options filter menu toggle');

describe(Cypress.spec.relative, () => {
    it('should correctly handle applied filters', () => {
        setup();

        // Set the entity type to 'Namespace'
        searchOptionsDropdown().click();
        cy.findByRole('option', { name: 'Namespace' }).click();
        searchOptionsDropdown().click();
        searchOptionsDropdown().should('have.text', 'Namespace');

        // Apply a namespace filter
        cy.findByRole('input', { name: 'Namespace' }).click();
        cy.findByRole('input', { name: 'Namespace' }).type('stackrox');
        cy.findByRole('option', { name: 'stackrox' }).click();
        cy.findByRole('input', { name: 'Namespace' }).click();

        // Apply a severity filter
        cy.findByText('CVE Severity').click();
        cy.findByRole('option', { name: 'Critical' }).click();
        cy.findByRole('option', { name: 'Important' }).click();
        cy.findByText('CVE Severity').click();

        // Check that the filters are applied in the toolbar chips
        cy.findByRole('group', { name: 'Namespace' }).within(() => {
            cy.findByRole('listitem', { name: 'stackrox' });
        });

        cy.findByRole('group', { name: 'Severity' }).within(() => {
            cy.findByRole('listitem', { name: 'Critical' });
            cy.findByRole('listitem', { name: 'Important' });
            cy.findByRole('listitem', { name: 'Moderate' }).should('not.exist');
            cy.findByRole('listitem', { name: 'Low' }).should('not.exist');
        });

        // Test removing filters
        cy.findByRole('listitem', { name: 'Important' }).within(() => {
            cy.findByLabel('close').click();
        });
        cy.findByRole('listitem', { name: 'Important' }).should('not.exist');

        // Clear remaining filters
        cy.findByText('Clear filters').click();

        // Check that the filters are removed from the toolbar chips
        cy.findByRole('group', { name: 'Severity' }).should('not.exist');
        cy.findByRole('group', { name: 'Namespace' }).should('not.exist');
    });
});
