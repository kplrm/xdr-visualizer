import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonIcon,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiHorizontalRule,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiSuperDatePicker,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';
import { DataPublicPluginStart } from '../../../OpenSearch-Dashboards/src/plugins/data/public';
import {
  AlertEventGraphResponse,
  AlertsSummaryResponse,
  EventGraphEdge,
  EventGraphNode,
  VisualizerAlertItem,
} from '../../common';

interface Props {
  basename: string;
  http: CoreStart['http'];
  notifications: CoreStart['notifications'];
  data?: DataPublicPluginStart;
}

type SeverityKey = 'critical' | 'high' | 'medium' | 'low';

const SEVERITY_ORDER: SeverityKey[] = ['critical', 'high', 'medium', 'low'];

const SEVERITY_COLORS: Record<SeverityKey, string> = {
  critical: '#d36086',
  high: '#e7664c',
  medium: '#f5a700',
  low: '#54b399',
};

const severityKeyFromValue = (value: number): SeverityKey => {
  if (value >= 9) {
    return 'critical';
  }
  if (value >= 7) {
    return 'high';
  }
  if (value >= 4) {
    return 'medium';
  }
  return 'low';
};

const donutBackground = (summary: AlertsSummaryResponse | null): string => {
  if (!summary || summary.total <= 0) {
    return '#d3dae6';
  }
  const map = new Map(summary.bySeverity.map((bucket) => [bucket.key, bucket.count]));
  let start = 0;
  const stops: string[] = [];
  for (const key of SEVERITY_ORDER) {
    const count = map.get(key) ?? 0;
    const pct = (count / summary.total) * 100;
    const end = Math.min(100, start + pct);
    stops.push(`${SEVERITY_COLORS[key]} ${start.toFixed(2)}% ${end.toFixed(2)}%`);
    start = end;
  }
  if (start < 100) {
    stops.push(`#d3dae6 ${start.toFixed(2)}% 100%`);
  }
  return `conic-gradient(${stops.join(', ')})`;
};

// NODE_W / NODE_H: size of a process/alert node box in the SVG
const NODE_W = 200;
const NODE_H = 72;
// Horizontal gap between depth levels, vertical gap between siblings
const LEVEL_GAP = 280;
const ROW_GAP = 110;
const CANVAS_PAD_X = 60;
const CANVAS_PAD_Y = 60;

function fmtTimeDelta(fromTs: string | undefined, toTs: string | undefined): string {
  if (!fromTs || !toTs) {
    return '';
  }
  const diff = Math.abs(new Date(toTs).getTime() - new Date(fromTs).getTime());
  if (isNaN(diff)) {
    return '';
  }
  if (diff < 1000) {
    return `${diff}ms`;
  }
  if (diff < 60000) {
    return `${(diff / 1000).toFixed(1)}s`;
  }
  if (diff < 3600000) {
    return `${Math.round(diff / 60000)}m`;
  }
  return `${(diff / 3600000).toFixed(1)}h`;
}

interface ProcessTreeLayout {
  // process/alert nodes (no file/event nodes)
  treeNodes: EventGraphNode[];
  // artifacts grouped by the process node id they belong to
  artifactsByProcess: Map<string, EventGraphNode[]>;
  // alert nodes grouped by the process node id they are attached to
  alertsByProcess: Map<string, EventGraphNode[]>;
  // only parent_of edges between tree-nodes
  treeEdges: Array<{ edge: EventGraphEdge; fromNode: EventGraphNode; toNode: EventGraphNode }>;
  positions: Map<string, { x: number; y: number }>;
  width: number;
  height: number;
}

function buildProcessTree(
  nodes: EventGraphNode[],
  edges: EventGraphEdge[],
  _alertId: string
): ProcessTreeLayout {
  const nodeById = new Map(nodes.map((n) => [n.id, n]));

  // Keep only process nodes in the tree layout; alerts/files are overlays.
  const processNodes = nodes.filter((n) => n.kind === 'process');

  // For alert nodes: find which process they are triggered_by
  const alertsByProcess = new Map<string, EventGraphNode[]>();
  for (const edge of edges) {
    if (edge.relation === 'triggered_by') {
      const alertNode = nodeById.get(edge.from);
      const procNode = nodeById.get(edge.to);
      if (alertNode && procNode && alertNode.kind === 'alert') {
        const arr = alertsByProcess.get(procNode.id) ?? [];
        // avoid duplicates
        if (!arr.find((a) => a.id === alertNode.id)) {
          arr.push(alertNode);
        }
        alertsByProcess.set(procNode.id, arr);
      }
    }
  }

  // For file nodes: find which process they are touched by (touches edge)
  const artifactsByProcess = new Map<string, EventGraphNode[]>();
  for (const edge of edges) {
    if (edge.relation === 'touches') {
      const procNode = nodeById.get(edge.from);
      const fileNode = nodeById.get(edge.to);
      if (procNode && fileNode && fileNode.kind === 'file') {
        const arr = artifactsByProcess.get(procNode.id) ?? [];
        if (!arr.find((f) => f.id === fileNode.id)) {
          arr.push(fileNode);
        }
        artifactsByProcess.set(procNode.id, arr);
      }
    }
  }

  // Build tree edges (only parent_of between process nodes)
  const treeNodeIds = new Set(processNodes.map((n) => n.id));
  const rawTreeEdges = edges.filter(
    (e) => e.relation === 'parent_of' && treeNodeIds.has(e.from) && treeNodeIds.has(e.to)
  );
  const treeEdges = rawTreeEdges.map((edge) => ({
    edge,
    fromNode: nodeById.get(edge.from)!,
    toNode: nodeById.get(edge.to)!,
  }));

  // Build parent/child maps for process sequence ordering.
  const childrenOf = new Map<string, string[]>();
  const parentsOf = new Map<string, string[]>();
  for (const { edge } of treeEdges) {
    const arr = childrenOf.get(edge.from) ?? [];
    arr.push(edge.to);
    childrenOf.set(edge.from, arr);
    const parr = parentsOf.get(edge.to) ?? [];
    parr.push(edge.from);
    parentsOf.set(edge.to, parr);
  }

  // Roots = oldest originators in process chain (no process parent in this graph).
  const roots = processNodes
    .filter((n) => !parentsOf.has(n.id) || parentsOf.get(n.id)!.length === 0)
    .sort((a, b) => String(a.timestamp ?? '').localeCompare(String(b.timestamp ?? '')));

  const depth = new Map<string, number>();
  const positioned = new Set<string>();
  const positions = new Map<string, { x: number; y: number }>();

  const normalizedChildren = (nodeId: string): string[] => {
    const children = childrenOf.get(nodeId) ?? [];
    return [...children].sort((a, b) => {
      const an = nodeById.get(a);
      const bn = nodeById.get(b);
      return String(an?.timestamp ?? '').localeCompare(String(bn?.timestamp ?? ''));
    });
  };

  // Lay out lineage in sequence order: parent left, direct child right.
  const layoutFrom = (nodeId: string, row: number, currentDepth: number): number => {
    const prevDepth = depth.get(nodeId);
    depth.set(nodeId, Math.max(prevDepth ?? 0, currentDepth));
    positions.set(nodeId, {
      x: CANVAS_PAD_X + (depth.get(nodeId) ?? currentDepth) * LEVEL_GAP,
      y: CANVAS_PAD_Y + row * ROW_GAP,
    });
    positioned.add(nodeId);

    const children = normalizedChildren(nodeId).filter((id) => treeNodeIds.has(id));
    if (children.length === 0) {
      return row + 1;
    }

    let nextRow = row;
    children.forEach((childId, idx) => {
      const childRow = idx === 0 ? row : nextRow;
      nextRow = layoutFrom(childId, childRow, (depth.get(nodeId) ?? currentDepth) + 1);
    });
    return nextRow;
  };

  let rowCursor = 0;
  for (const root of roots) {
    if (!positioned.has(root.id)) {
      rowCursor = layoutFrom(root.id, rowCursor, 0);
    }
  }

  // Any disconnected process node still gets a slot.
  for (const node of processNodes) {
    if (!positioned.has(node.id)) {
      rowCursor = layoutFrom(node.id, rowCursor, 0);
    }
  }

  const width = Math.max(
    800,
    ...[...positions.values()].map((p) => p.x + NODE_W + CANVAS_PAD_X)
  );
  const height = Math.max(
    400,
    ...[...positions.values()].map((p) => p.y + NODE_H + CANVAS_PAD_Y + 40)
  );

  return { treeNodes: processNodes, artifactsByProcess, alertsByProcess, treeEdges, positions, width, height };
}

// Popup state: which process node has its artifact list open
type ArtifactPopup = { nodeId: string; x: number; y: number } | null;

export const XdrVisualizerApp = ({ http, notifications, data }: Props) => {
  const [timeRange, setTimeRange] = useState<{ from: string; to: string }>({ from: 'now-24h', to: 'now' });
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [hostFilter, setHostFilter] = useState<string>('');
  const [summary, setSummary] = useState<AlertsSummaryResponse | null>(null);
  const [loadingSummary, setLoadingSummary] = useState<boolean>(false);
  const [selectedAlertId, setSelectedAlertId] = useState<string>('');
  const [graph, setGraph] = useState<AlertEventGraphResponse | null>(null);
  const [loadingGraph, setLoadingGraph] = useState<boolean>(false);
  const [graphFullscreen, setGraphFullscreen] = useState<boolean>(false);
  const [artifactPopup, setArtifactPopup] = useState<ArtifactPopup>(null);
  const [pageIndex, setPageIndex] = useState<number>(0);
  const [pageSize] = useState<number>(20);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const timefilter = data?.query?.timefilter?.timefilter;
    if (!timefilter) {
      return undefined;
    }

    const syncTime = () => {
      const next = timefilter.getTime();
      setTimeRange({ from: String(next.from ?? 'now-24h'), to: String(next.to ?? 'now') });
    };

    syncTime();
    const sub = timefilter.getTimeUpdate$().subscribe(syncTime);
    return () => sub.unsubscribe();
  }, [data]);

  const loadSummary = useCallback(async () => {
    setLoadingSummary(true);
    try {
      const body = await http.get('/api/xdr-visualizer/alerts/summary', {
        query: {
          from: timeRange.from,
          to: timeRange.to,
          ...(severityFilter ? { severity: severityFilter } : {}),
          ...(hostFilter ? { host: hostFilter } : {}),
        },
      });
      setSummary(body as AlertsSummaryResponse);
      setPageIndex(0);
      const recent = (body as AlertsSummaryResponse).recentAlerts;
      if (!selectedAlertId && recent.length > 0) {
        setSelectedAlertId(recent[0].id);
      }
    } catch (err: any) {
      notifications.toasts.addDanger({
        title: 'Failed to load alert summary',
        text: String(err?.body?.message ?? err?.message ?? err),
      });
    } finally {
      setLoadingSummary(false);
    }
  }, [timeRange.from, timeRange.to, severityFilter, hostFilter, http, notifications, selectedAlertId]);

  const loadGraph = useCallback(async () => {
    if (!selectedAlertId) {
      setGraph(null);
      return;
    }
    setLoadingGraph(true);
    try {
      const body = await http.get('/api/xdr-visualizer/alerts/events', {
        query: { alert_id: selectedAlertId, from: timeRange.from, to: timeRange.to },
      });
      setGraph(body as AlertEventGraphResponse);
    } catch (err: any) {
      notifications.toasts.addDanger({
        title: 'Failed to load event graph',
        text: String(err?.body?.message ?? err?.message ?? err),
      });
    } finally {
      setLoadingGraph(false);
    }
  }, [selectedAlertId, timeRange.from, timeRange.to, http, notifications]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const hostOptions = useMemo(() => {
    const hosts = summary?.byHost ?? [];
    return hosts.map((entry) => entry.key).filter((entry) => entry && entry !== 'unknown');
  }, [summary]);

  const tableColumns = [
    {
      field: 'timestamp',
      name: '@timestamp',
      width: '220px',
      render: (value: string) => (
        <span style={{ whiteSpace: 'nowrap', display: 'inline-block', paddingRight: 8 }}>
          {value?.replace('T', ' ').replace('Z', '')}
        </span>
      ),
    },
    {
      field: 'severity',
      name: 'Severity',
      width: '130px',
      render: (value: number) => {
        const sev = severityKeyFromValue(value);
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap', paddingLeft: 4 }}>
            <EuiHealth color={SEVERITY_COLORS[sev]}>{sev}</EuiHealth>
          </span>
        );
      },
    },
    {
      field: 'ruleName',
      name: 'Rule',
      width: '260px',
      render: (value: string, item: VisualizerAlertItem) => (
        <span style={{ whiteSpace: 'nowrap' }} title={value || item.ruleId}>{value || item.ruleId || '-'}</span>
      ),
    },
    {
      field: 'processName',
      name: 'Process',
      width: '160px',
      render: (value: string, item: VisualizerAlertItem) => {
        const display = value || item.processCommandLine;
        return <span style={{ whiteSpace: 'nowrap' }} title={display}>{display || '-'}</span>;
      },
    },
    {
      field: 'filePath',
      name: 'Artifact',
      width: '260px',
      render: (value: string, item: VisualizerAlertItem) => {
        const display = value || item.processCommandLine;
        return <span style={{ whiteSpace: 'nowrap' }} title={display}>{display || '-'}</span>;
      },
    },
    {
      field: 'host',
      name: 'Host',
      width: '150px',
      render: (value: string) => <span style={{ whiteSpace: 'nowrap' }}>{value}</span>,
    },
  ];

  const rows = summary?.recentAlerts ?? [];
  const pagination = {
    pageIndex,
    pageSize,
    totalItemCount: rows.length,
    pageSizeOptions: [20],
  };
  const selected = rows.find((row) => row.id === selectedAlertId);
  const processTree = useMemo(
    () => (graph ? buildProcessTree(graph.nodes, graph.edges, graph.alertId) : null),
    [graph]
  );

  // Close popup when graph changes
  useEffect(() => {
    setArtifactPopup(null);
  }, [graph]);

  return (
    <div style={{ padding: 16 }}>
      <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" gutterSize="m">
        <EuiFlexItem grow={false}>
          <EuiTitle size="l">
            <h1>Threat Visualizer</h1>
          </EuiTitle>
          <EuiText size="s" color="subdued">
            Hunt attack footprints through correlated alerts, process lineage, and touched artifacts.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiFlexGroup gutterSize="s" alignItems="center">
            <EuiFlexItem grow={false}>
                <EuiSuperDatePicker
                  start={timeRange.from}
                  end={timeRange.to}
                  onTimeChange={({ start, end }) => {
                    setTimeRange({ from: start, to: end });
                    data?.query?.timefilter?.timefilter?.setTime({ from: start, to: end });
                  }}
                  isPaused={data?.query?.timefilter?.timefilter?.getRefreshInterval()?.pause ?? true}
                  refreshInterval={data?.query?.timefilter?.timefilter?.getRefreshInterval()?.value ?? 0}
                  onRefreshChange={({ isPaused, refreshInterval }) => {
                    data?.query?.timefilter?.timefilter?.setRefreshInterval({
                      pause: isPaused,
                      value: refreshInterval,
                    });
                  }}
                  showUpdateButton={false}
                  compressed
                />
            </EuiFlexItem>
            <EuiFlexItem grow={false}>
              <EuiButton size="s" fill onClick={loadSummary} isLoading={loadingSummary}>
                Refresh
              </EuiButton>
            </EuiFlexItem>
          </EuiFlexGroup>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />

      <EuiFlexGroup gutterSize="m" alignItems="stretch">
        <EuiFlexItem grow={3}>
          <EuiPanel hasShadow style={{ minHeight: 360, background: 'linear-gradient(135deg, #f5f7fa 0%, #eef2f8 100%)' }}>
            <EuiTitle size="s">
              <h2>Alert Spectrum</h2>
            </EuiTitle>
            <EuiText size="s" color="subdued">Click a severity slice to filter results.</EuiText>
            <EuiSpacer size="m" />
            {loadingSummary && <EuiLoadingSpinner size="xl" />}
            {!loadingSummary && summary && (
              <EuiFlexGroup alignItems="center" gutterSize="l">
                <EuiFlexItem grow={false}>
                  <div
                    style={{
                      width: 200,
                      height: 200,
                      borderRadius: '50%',
                      background: donutBackground(summary),
                      position: 'relative',
                      boxShadow: 'inset 0 0 0 18px rgba(255,255,255,0.95), 0 12px 28px rgba(0,0,0,0.08)',
                    }}
                  >
                    <div
                      style={{
                        position: 'absolute',
                        inset: 52,
                        borderRadius: '50%',
                        background: '#fff',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexDirection: 'column',
                        fontWeight: 700,
                      }}
                    >
                      <span style={{ fontSize: 24 }}>{summary.total.toLocaleString()}</span>
                      <span style={{ fontSize: 12, color: '#69707d' }}>alerts</span>
                    </div>
                  </div>
                </EuiFlexItem>
                <EuiFlexItem>
                  <EuiFlexGroup direction="column" gutterSize="s">
                    {SEVERITY_ORDER.map((sev) => {
                      const bucket = summary.bySeverity.find((entry) => entry.key === sev);
                      const count = bucket?.count ?? 0;
                      const active = severityFilter === sev;
                      return (
                        <EuiFlexItem key={sev} grow={false}>
                          <div
                            role="button"
                            tabIndex={0}
                            onClick={() => setSeverityFilter(active ? '' : sev)}
                            onKeyDown={(event) => {
                              if (event.key === 'Enter') {
                                setSeverityFilter(active ? '' : sev);
                              }
                            }}
                            style={{
                              cursor: 'pointer',
                              borderRadius: 10,
                              padding: 10,
                              border: active ? `2px solid ${SEVERITY_COLORS[sev]}` : '1px solid #d3dae6',
                              background: active ? `${SEVERITY_COLORS[sev]}16` : '#fff',
                            }}
                          >
                            <EuiFlexGroup justifyContent="spaceBetween" alignItems="center" gutterSize="s">
                              <EuiFlexItem grow={false}>
                                <EuiHealth color={SEVERITY_COLORS[sev]}>{sev}</EuiHealth>
                              </EuiFlexItem>
                              <EuiFlexItem grow={false}>
                                <EuiBadge color="hollow">{count.toLocaleString()}</EuiBadge>
                              </EuiFlexItem>
                            </EuiFlexGroup>
                          </div>
                        </EuiFlexItem>
                      );
                    })}
                  </EuiFlexGroup>
                </EuiFlexItem>
              </EuiFlexGroup>
            )}
          </EuiPanel>
        </EuiFlexItem>

        <EuiFlexItem grow={2}>
          <EuiPanel hasShadow style={{ minHeight: 360 }}>
            <EuiTitle size="s">
              <h2>Recent Alerts</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s" alignItems="center">
              <EuiFlexItem grow={false}>
                <EuiBadge color={severityFilter ? 'accent' : 'hollow'}>
                  Severity: {severityFilter || 'all'}
                </EuiBadge>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiBadge color={hostFilter ? 'accent' : 'hollow'}>
                  Host: {hostFilter || 'all'}
                </EuiBadge>
              </EuiFlexItem>
              {hostOptions.map((host) => (
                <EuiFlexItem grow={false} key={host}>
                  <EuiButton size="s" color={hostFilter === host ? 'primary' : 'text'} onClick={() => setHostFilter(hostFilter === host ? '' : host)}>
                    {host}
                  </EuiButton>
                </EuiFlexItem>
              ))}
            </EuiFlexGroup>
            <EuiSpacer size="s" />
            {/* Scrollable table with fixed-width nowrap columns */}
            <div style={{ maxHeight: 320, overflowY: 'auto', overflowX: 'auto' }}>
              <div style={{ minWidth: 1200 }}>
                <EuiBasicTable<VisualizerAlertItem>
                  compressed
                  items={rows}
                  columns={tableColumns}
                  pagination={pagination}
                  onChange={({ page }: any) => {
                    if (page) {
                      setPageIndex(page.index);
                    }
                  }}
                  rowProps={(item) => ({
                    onClick: () => setSelectedAlertId(item.id),
                    style: {
                      cursor: 'pointer',
                      backgroundColor: selectedAlertId === item.id ? '#f0f7ff' : undefined,
                    },
                  })}
                />
              </div>
            </div>
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />
      <EuiHorizontalRule margin="m" />

      <EuiPanel
        hasShadow
        style={
          graphFullscreen
            ? {
                position: 'fixed',
                inset: 12,
                zIndex: 1600,
                overflow: 'auto',
                background: '#ffffff',
              }
            : undefined
        }
      >
        <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s">
          <EuiFlexItem grow={false}>
            <EuiTitle size="s">
              <h2>Attack Footprint Graph</h2>
            </EuiTitle>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiFlexGroup gutterSize="s" alignItems="center">
              <EuiFlexItem grow={false}>
                <EuiButtonIcon
                  iconType={graphFullscreen ? 'fullScreenExit' : 'fullScreen'}
                  aria-label={graphFullscreen ? 'Exit full screen' : 'Enter full screen'}
                  onClick={() => setGraphFullscreen(!graphFullscreen)}
                />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton size="s" onClick={loadGraph} isLoading={loadingGraph}>
                  Reload Graph
                </EuiButton>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiSpacer size="s" />

        {selected && (
          <EuiCallOut color="primary" size="s" iconType="search">
            <strong>Selected alert:</strong> {selected.ruleName || selected.ruleId || selected.id}
            {' · '}
            {selected.host}
            {' · '}
            {selected.timestamp}
          </EuiCallOut>
        )}

        <EuiSpacer size="m" />

        {loadingGraph && <EuiLoadingSpinner size="xl" />}

        {!loadingGraph && (!graph || graph.nodes.length === 0) && (
          <EuiCallOut color="warning" title="No related events found for this alert in the selected window." iconType="alert" />
        )}

        {!loadingGraph && graph && processTree && (
          <div
            style={{
              overflowX: 'auto',
              overflowY: 'auto',
              maxHeight: graphFullscreen ? 'calc(100vh - 200px)' : 560,
              border: '1px solid #d3dae6',
              borderRadius: 8,
              background: '#f9fbfd',
              position: 'relative',
            }}
            onClick={() => setArtifactPopup(null)}
          >
            <svg ref={svgRef} width={processTree.width} height={processTree.height}>
              {/* Parent-of edges with time delta labels */}
              {processTree.treeEdges.map(({ edge, fromNode, toNode }) => {
                const from = processTree.positions.get(edge.from);
                const to = processTree.positions.get(edge.to);
                if (!from || !to) {
                  return null;
                }
                const x1 = from.x + NODE_W;
                const y1 = from.y + NODE_H / 2;
                const x2 = to.x;
                const y2 = to.y + NODE_H / 2;
                const mx = (x1 + x2) / 2;
                const my = (y1 + y2) / 2;
                const delta = fmtTimeDelta(fromNode.timestamp, toNode.timestamp);
                return (
                  <g key={edge.id}>
                    <line
                      x1={x1}
                      y1={y1}
                      x2={x2}
                      y2={y2}
                      stroke="#0077cc"
                      strokeWidth={2}
                    />
                    {/* Arrow head */}
                    <polygon
                      points={`${x2},${y2} ${x2 - 10},${y2 - 5} ${x2 - 10},${y2 + 5}`}
                      fill="#0077cc"
                    />
                    {delta && (
                      <g>
                        <rect x={mx - 18} y={my - 10} width={36} height={16} rx={3} fill="#e8f4fd" stroke="#0077cc" strokeWidth={0.5} />
                        <text x={mx} y={my + 3} textAnchor="middle" fontSize="10" fill="#0077cc">{delta}</text>
                      </g>
                    )}
                  </g>
                );
              })}

              {/* Process nodes */}
              {processTree.treeNodes.map((node) => {
                const pos = processTree.positions.get(node.id);
                if (!pos) {
                  return null;
                }
                const alerts = processTree.alertsByProcess.get(node.id) ?? [];
                const artifacts = processTree.artifactsByProcess.get(node.id) ?? [];
                const artifactPopupOpen = artifactPopup?.nodeId === node.id;

                // Count artifacts by type
                const fileCount = artifacts.filter((a) => a.type === 'file.path' || (a.filePath && !a.module?.includes('library'))).length;
                const libCount = artifacts.filter((a) => a.module?.includes('library')).length;

                const artifactBtnY = pos.y + NODE_H - 18;

                return (
                  <g key={node.id}>
                    {/* Node box */}
                    <rect
                      x={pos.x}
                      y={pos.y}
                      width={NODE_W}
                      height={NODE_H}
                      rx={8}
                      fill="#fff"
                      stroke="#0077cc"
                      strokeWidth={2}
                    />
                    {/* Process label */}
                    <text x={pos.x + 10} y={pos.y + 18} fill="#0077cc" fontSize="11" fontWeight="bold">
                      PROCESS
                    </text>
                    <text x={pos.x + 10} y={pos.y + 34} fill="#1a1c21" fontSize="12">
                      {(node.processName || node.label).slice(0, 24)}
                    </text>
                    <text x={pos.x + 10} y={pos.y + 50} fill="#69707d" fontSize="10">
                      {(node.processCommandLine || node.filePath || '').slice(0, 30)}
                    </text>

                    {/* Alert badges — show above the node for each alert */}
                    {alerts.map((alertNode, alertIdx) => {
                      const badgeX = pos.x + alertIdx * 8;
                      const badgeY = pos.y - 26;
                      return (
                        <g key={alertNode.id}>
                          {/* Dashed line from alert badge to node */}
                          <line
                            x1={badgeX + NODE_W / 2}
                            y1={badgeY + 22}
                            x2={pos.x + NODE_W / 2}
                            y2={pos.y}
                            stroke="#f04e98"
                            strokeWidth={1.5}
                            strokeDasharray="4 3"
                          />
                          <rect
                            x={badgeX}
                            y={badgeY}
                            width={NODE_W}
                            height={22}
                            rx={5}
                            fill="#fce4ef"
                            stroke="#f04e98"
                            strokeWidth={1.5}
                          />
                          <title>{alertNode.label}</title>
                          <text x={badgeX + 6} y={badgeY + 14} fill="#d63384" fontSize="10" fontWeight="bold">
                            ⚠ {alertNode.label.slice(0, 28)}
                          </text>
                        </g>
                      );
                    })}

                    {/* Artifact count button at bottom of node */}
                    {artifacts.length > 0 && (
                      <g
                        style={{ cursor: 'pointer' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setArtifactPopup(
                            artifactPopupOpen
                              ? null
                              : { nodeId: node.id, x: pos.x, y: pos.y + NODE_H + 8 }
                          );
                        }}
                      >
                        <rect
                          x={pos.x + (NODE_W - 120) / 2}
                          y={artifactBtnY - 2}
                          width={120}
                          height={18}
                          rx={9}
                          fill={artifactPopupOpen ? '#017d73' : '#e0f5f1'}
                          stroke="#017d73"
                          strokeWidth={1}
                        />
                        <text
                          x={pos.x + NODE_W / 2}
                          y={artifactBtnY + 10}
                          textAnchor="middle"
                          fontSize="10"
                          fill={artifactPopupOpen ? '#fff' : '#017d73'}
                          fontWeight="bold"
                        >
                          {fileCount > 0 && `${fileCount} file${fileCount !== 1 ? 's' : ''}`}
                          {fileCount > 0 && libCount > 0 && '  ·  '}
                          {libCount > 0 && `${libCount} lib${libCount !== 1 ? 's' : ''}`}
                          {fileCount === 0 && libCount === 0 && `${artifacts.length} artifact${artifacts.length !== 1 ? 's' : ''}`}
                        </text>
                      </g>
                    )}

                    {/* Artifact popup */}
                    {artifactPopupOpen && artifactPopup && (
                      <g onClick={(e) => e.stopPropagation()}>
                        {(() => {
                          const popX = artifactPopup.x;
                          const popY = artifactPopup.y;
                          const lineH = 18;
                          const popH = 28 + artifacts.length * lineH;
                          const popW = Math.max(260, NODE_W + 60);
                          return (
                            <>
                              <rect
                                x={popX}
                                y={popY}
                                width={popW}
                                height={popH}
                                rx={6}
                                fill="#fff"
                                stroke="#017d73"
                                strokeWidth={1.5}
                                filter="url(#shadow)"
                              />
                              <text x={popX + 10} y={popY + 16} fontSize="11" fontWeight="bold" fill="#017d73">
                                Artifacts ({artifacts.length})
                              </text>
                              {artifacts.map((art, artIdx) => (
                                <text key={art.id} x={popX + 10} y={popY + 28 + artIdx * lineH} fontSize="10" fill="#343741">
                                  {(art.filePath || art.label).slice(0, 46)}
                                </text>
                              ))}
                            </>
                          );
                        })()}
                      </g>
                    )}
                  </g>
                );
              })}

              {/* Drop-shadow filter definition */}
              <defs>
                <filter id="shadow" x="-10%" y="-10%" width="120%" height="130%">
                  <feDropShadow dx="2" dy="4" stdDeviation="4" floodColor="#00000022" />
                </filter>
              </defs>
            </svg>
          </div>
        )}

        <EuiSpacer size="s" />
        <EuiText size="xs" color="subdued">
          Process tree shows parent→child lineage left to right. Alert badges appear above the triggering process. Click the artifact count badge to see touched files. Edge labels show time between process start events.
        </EuiText>
      </EuiPanel>

      <EuiSpacer size="l" />
      <EuiToolTip content="Clear severity and host filters">
        <EuiButton color="text" size="s" onClick={() => { setSeverityFilter(''); setHostFilter(''); }}>
          Reset filters
        </EuiButton>
      </EuiToolTip>
    </div>
  );
};
