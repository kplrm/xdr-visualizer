export const PLUGIN_ID = 'xdrVisualizer';
export const PLUGIN_NAME = 'XDR Visualizer';

export const PLUGIN_CATEGORY = {
  id: 'xdrSecurity',
  label: 'XDR Security',
  order: 2200,
};

export interface AlertSummaryBucket {
  key: string;
  count: number;
}

export interface VisualizerAlertItem {
  id: string;
  timestamp: string;
  host: string;
  severity: number;
  module: string;
  ruleId?: string;
  ruleName?: string;
  action?: string;
  sourceModule?: string;
  sourceType?: string;
  processEntityId?: string;
  processName?: string;
  processCommandLine?: string;
  filePath?: string;
}

export interface AlertsSummaryResponse {
  total: number;
  bySeverity: AlertSummaryBucket[];
  byRule: AlertSummaryBucket[];
  byHost: AlertSummaryBucket[];
  recentAlerts: VisualizerAlertItem[];
}

export interface EventGraphNode {
  id: string;
  timestamp?: string;
  label: string;
  kind: 'alert' | 'event' | 'process' | 'file';
  module?: string;
  type?: string;
  host?: string;
  processEntityId?: string;
  processParentEntityId?: string;
  processName?: string;
  processCommandLine?: string;
  filePath?: string;
}

export interface EventGraphEdge {
  id: string;
  from: string;
  to: string;
  relation: 'triggered_by' | 'parent_of' | 'touches' | 'temporal';
}

export interface AlertEventGraphResponse {
  alertId: string;
  nodes: EventGraphNode[];
  edges: EventGraphEdge[];
}
