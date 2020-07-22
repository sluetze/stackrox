/**
 * This file is intentionally `.tsx` so CRA will detect that the app can be compiled with TypeScript.
 * The rest of the files can be either TypeScript (.ts or .tsx) or JavaScript (.js).
 */

import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';
import { ConnectedRouter } from 'react-router-redux';
import { createBrowserHistory as createHistory } from 'history';
import { ApolloProvider } from '@apollo/client';
import 'typeface-open-sans';
import 'typeface-open-sans-condensed';
// eslint-disable-next-line
import 'index.css'; // this file is generated by tailwind (see package.json scripts)
// eslint-disable-next-line no-unused-vars

import ErrorBoundary from 'Containers/ErrorBoundary';
import AppPage from 'Containers/AppPage';
import { ThemeProvider } from 'Containers/ThemeProvider';
import ExportingInProgress from 'Containers/ExportingPDFInProgress';
import configureStore from 'store/configureStore';
import installRaven from 'installRaven';
import configureApollo from './configureApolloClient';

installRaven();

const rootNode = document.getElementById('root');
const history = createHistory();
const store = configureStore(undefined, history);
const apolloClient = configureApollo();

ReactDOM.render(
    <Provider store={store}>
        <ApolloProvider client={apolloClient}>
            <ConnectedRouter history={history}>
                <ThemeProvider>
                    <ErrorBoundary>
                        <AppPage />
                        <ExportingInProgress />
                    </ErrorBoundary>
                </ThemeProvider>
            </ConnectedRouter>
        </ApolloProvider>
    </Provider>,
    rootNode
);
