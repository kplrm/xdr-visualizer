import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreStart } from '../../OpenSearch-Dashboards/src/core/public';
import { DataPublicPluginStart } from '../../OpenSearch-Dashboards/src/plugins/data/public';
import { XdrVisualizerApp } from './components';

interface XdrVisualizerStartDeps {
  data?: DataPublicPluginStart;
}

export const renderApp = (
  { http, notifications }: CoreStart,
  depsStart: XdrVisualizerStartDeps,
  { appBasePath, element }: AppMountParameters
) => {
  ReactDOM.render(
    <XdrVisualizerApp basename={appBasePath} http={http} notifications={notifications} data={depsStart.data} />,
    element
  );
  return () => ReactDOM.unmountComponentAtNode(element);
};
