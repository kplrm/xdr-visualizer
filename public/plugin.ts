import { AppMountParameters, CoreSetup, CoreStart, Plugin } from '../../OpenSearch-Dashboards/src/core/public';
import { DataPublicPluginStart } from '../../OpenSearch-Dashboards/src/plugins/data/public';
import { PLUGIN_CATEGORY, PLUGIN_ID, PLUGIN_NAME } from '../common';

interface XdrVisualizerStartDeps {
  data?: DataPublicPluginStart;
}

type XdrVisualizerSetupContract = Record<string, never>;
type XdrVisualizerStartContract = Record<string, never>;
type XdrVisualizerSetupDeps = Record<string, never>;

export class XdrVisualizerPlugin implements Plugin<
  XdrVisualizerSetupContract,
  XdrVisualizerStartContract,
  XdrVisualizerSetupDeps,
  XdrVisualizerStartDeps
> {
  public setup(core: CoreSetup) {
    core.application.register({
      id: PLUGIN_ID,
      title: PLUGIN_NAME,
      order: 3,
      category: PLUGIN_CATEGORY,
      async mount(params: AppMountParameters) {
        const { renderApp } = await import('./application');
        const [coreStart, depsStart] = await core.getStartServices();
        return renderApp(coreStart, depsStart, params);
      },
    });
    return {};
  }

  public start(_core: CoreStart) {
    return {};
  }

  public stop() {}
}
