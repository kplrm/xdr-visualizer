import { registerVisualizerRoutes } from './routes';

export class XdrVisualizerServerPlugin {
  public setup(core: any) {
    const router = core.http.createRouter();
    registerVisualizerRoutes(router);
    return {};
  }

  public start() {
    return {};
  }

  public stop() {}
}
