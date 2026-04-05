import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiCodeBlock,
  EuiComboBox,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiHealth,
  EuiHorizontalRule,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiSuperDatePicker,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import { CoreStart } from '../../../OpenSearch-Dashboards/src/core/public';
import { DataPublicPluginStart } from '../../../OpenSearch-Dashboards/src/plugins/data/public';
import {
  AlertEventDetailsResponse,
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
const NODE_H = 120;
// Horizontal gap between depth levels, vertical gap between siblings
const LEVEL_GAP = 280;
const BASE_ROW_GAP = 110;
const CANVAS_PAD_X = 60;
const CANVAS_PAD_Y = 64;
const ALERT_NODE_H = 22;
const ALERT_NODE_GAP = 10;

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
  // fixed position for each alert box
  alertPositions: Map<string, { x: number; y: number }>;
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
      const artifactNode = nodeById.get(edge.to);
      if (procNode && artifactNode && artifactNode.kind === 'artifact') {
        const arr = artifactsByProcess.get(procNode.id) ?? [];
        if (!arr.find((f) => f.id === artifactNode.id)) {
          arr.push(artifactNode);
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
  const rowByNodeId = new Map<string, number>();
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
    rowByNodeId.set(nodeId, row);
    positions.set(nodeId, {
      x: CANVAS_PAD_X + (depth.get(nodeId) ?? currentDepth) * LEVEL_GAP,
      y: CANVAS_PAD_Y + row * BASE_ROW_GAP,
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

  // Reserve vertical space above rows with alerts so each alert stays near its process node.
  const maxRow = Math.max(0, ...[...rowByNodeId.values()]);
  const rowMaxAlertCount = new Array(maxRow + 1).fill(0);
  for (const node of processNodes) {
    const row = rowByNodeId.get(node.id);
    if (row === undefined) {
      continue;
    }
    const alertCount = (alertsByProcess.get(node.id) ?? []).length;
    if (alertCount > rowMaxAlertCount[row]) {
      rowMaxAlertCount[row] = alertCount;
    }
  }
  const rowAlertReserve = rowMaxAlertCount.map((count) => (count > 0 ? count * (ALERT_NODE_H + ALERT_NODE_GAP) + 8 : 0));
  const cumulativeReserveBeforeRow = new Array(maxRow + 1).fill(0);
  for (let row = 1; row <= maxRow; row += 1) {
    cumulativeReserveBeforeRow[row] = cumulativeReserveBeforeRow[row - 1] + rowAlertReserve[row - 1];
  }
  for (const [nodeId, row] of rowByNodeId.entries()) {
    const pos = positions.get(nodeId);
    if (!pos) {
      continue;
    }
    positions.set(nodeId, {
      x: pos.x,
      y: CANVAS_PAD_Y + row * BASE_ROW_GAP + cumulativeReserveBeforeRow[row] + rowAlertReserve[row],
    });
  }

  const width = Math.max(
    800,
    ...[...positions.values()].map((p) => p.x + NODE_W + CANVAS_PAD_X)
  );

  const alertPositions = new Map<string, { x: number; y: number }>();
  for (const processNode of processNodes) {
    const nodePos = positions.get(processNode.id);
    if (!nodePos) {
      continue;
    }
    const processAlerts = alertsByProcess.get(processNode.id) ?? [];
    for (let idx = 0; idx < processAlerts.length; idx += 1) {
      const alertNode = processAlerts[idx];
      alertPositions.set(alertNode.id, {
        x: nodePos.x,
        y: nodePos.y - (idx + 1) * (ALERT_NODE_H + ALERT_NODE_GAP),
      });
    }
  }

  const height = Math.max(
    400,
    ...[...positions.values()].map((p) => p.y + NODE_H + CANVAS_PAD_Y + 40)
  );

  return {
    treeNodes: processNodes,
    artifactsByProcess,
    alertsByProcess,
    alertPositions,
    treeEdges,
    positions,
    width,
    height,
  };
}

// Popup state: which process node has its artifact list open
type ArtifactPopup = { nodeId: string; x: number; y: number } | null;
type HostOption = { label: string };

interface ProcessDetailsRequest {
  eventId?: string;
  processEntityId?: string;
  sourceKind?: 'process' | 'alert' | 'artifact';
}

interface DetailsFieldRow {
  field: string;
  value: string;
}

interface DetailsScrollPaneProps {
  children: React.ReactNode;
}

function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function scalarToDisplay(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

function flattenDocumentFields(value: unknown, prefix: string, out: DetailsFieldRow[]): void {
  if (value === null || value === undefined) {
    out.push({ field: prefix, value: '' });
    return;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      out.push({ field: prefix, value: '[]' });
      return;
    }
    for (let idx = 0; idx < value.length; idx += 1) {
      const nextKey = `${prefix}[${idx}]`;
      const item = value[idx];
      if (item && typeof item === 'object') {
        flattenDocumentFields(item, nextKey, out);
      } else {
        out.push({ field: nextKey, value: scalarToDisplay(item) });
      }
    }
    return;
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      out.push({ field: prefix, value: '{}' });
      return;
    }
    for (const [key, nested] of entries) {
      const nextKey = prefix ? `${prefix}.${key}` : key;
      if (nested && typeof nested === 'object') {
        flattenDocumentFields(nested, nextKey, out);
      } else {
        out.push({ field: nextKey, value: scalarToDisplay(nested) });
      }
    }
    return;
  }

  out.push({ field: prefix, value: scalarToDisplay(value) });
}

function toDetailsRows(source: Record<string, any> | null): DetailsFieldRow[] {
  if (!source) {
    return [];
  }
  const rows: DetailsFieldRow[] = [];
  flattenDocumentFields(source, '', rows);
  rows.sort((a, b) => a.field.localeCompare(b.field));
  return rows;
}

function DetailsScrollPane({ children }: DetailsScrollPaneProps): JSX.Element {
  return (
    <div style={{ flex: 1, minHeight: 0 }}>
      <div
        className="xdrDetailsScrollRegion"
        style={{
          height: '100%',
          overflowY: 'scroll',
          overflowX: 'hidden',
          paddingRight: 8,
          paddingBottom: 12,
          boxSizing: 'border-box',
          scrollbarGutter: 'stable',
          overscrollBehavior: 'contain',
        }}
      >
        {children}
      </div>
    </div>
  );
}

function isAbortedRequestError(err: any): boolean {
  const message = String(err?.body?.message ?? err?.message ?? err).toLowerCase();
  return message.includes('abort') || message.includes('cancel');
}

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
  const [selectedProcessNodeId, setSelectedProcessNodeId] = useState<string>('');
  const [selectedProcessDetails, setSelectedProcessDetails] = useState<Record<string, any> | null>(null);
  const [selectedProcessDetailsEventId, setSelectedProcessDetailsEventId] = useState<string>('');
  const [processDetailsError, setProcessDetailsError] = useState<string>('');
  const [processDetailsRequestLabel, setProcessDetailsRequestLabel] = useState<string>('');
  const [selectedDetailsKind, setSelectedDetailsKind] = useState<'process' | 'alert' | 'artifact'>('process');
  const [detailsViewTab, setDetailsViewTab] = useState<'table' | 'json'>('table');
  const [detailsSearchQuery, setDetailsSearchQuery] = useState<string>('');
  const [loadingProcessDetails, setLoadingProcessDetails] = useState<boolean>(false);
  const [pageIndex, setPageIndex] = useState<number>(0);
  const [pageSize] = useState<number>(20);
  const [graphZoom, setGraphZoom] = useState<number>(1);
  const [isPanningGraph, setIsPanningGraph] = useState<boolean>(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const panStateRef = useRef<{ active: boolean; startX: number; startY: number; scrollLeft: number; scrollTop: number }>({
    active: false,
    startX: 0,
    startY: 0,
    scrollLeft: 0,
    scrollTop: 0,
  });
  const detailsRequestSeqRef = useRef<number>(0);

  useEffect(() => {
    const timefilter = data?.query?.timefilter?.timefilter;
    if (!timefilter) {
      return undefined;
    }

    // Threat Visualizer default window is always last 24h on entry.
    timefilter.setTime({ from: 'now-24h', to: 'now' });

    const syncTime = () => {
      const next = timefilter.getTime();
      setTimeRange({ from: String(next.from ?? 'now-24h'), to: String(next.to ?? 'now') });
    };

    syncTime();
    const sub = timefilter.getTimeUpdate$().subscribe(syncTime);
    return () => sub.unsubscribe();
  }, [data]);

  useEffect(() => {
    if (!graphFullscreen) {
      return undefined;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setGraphFullscreen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [graphFullscreen]);

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

  const loadProcessDetails = useCallback(async ({ eventId, processEntityId, sourceKind }: ProcessDetailsRequest) => {
    if (!eventId && !processEntityId) {
      return;
    }
    const requestSeq = detailsRequestSeqRef.current + 1;
    detailsRequestSeqRef.current = requestSeq;

    const requestLabel = eventId
      ? `event_id=${eventId}`
      : `process_entity_id=${processEntityId}`;

    setSelectedDetailsKind(sourceKind ?? 'process');
    setDetailsViewTab('table');
    setDetailsSearchQuery('');
    setSelectedProcessNodeId(eventId || processEntityId || '');
    setLoadingProcessDetails(true);
    setProcessDetailsError('');
    setProcessDetailsRequestLabel(requestLabel);
    setSelectedProcessDetails(null);

    if (eventId && graph?.nodeSources && graph.nodeSources[eventId]) {
      setSelectedProcessDetails(graph.nodeSources[eventId]);
      setSelectedProcessDetailsEventId(eventId);
      setLoadingProcessDetails(false);
      return;
    }

    const queryBase: Record<string, string> = {
      ...(eventId ? { event_id: eventId } : {}),
      ...(processEntityId ? { process_entity_id: processEntityId } : {}),
    };

    try {
      let body: AlertEventDetailsResponse;
      try {
        body = await http.get('/api/xdr-visualizer/alerts/event', {
          query: {
            ...queryBase,
            from: timeRange.from,
            to: timeRange.to,
          },
        }) as AlertEventDetailsResponse;
      } catch (firstErr: any) {
        if (isAbortedRequestError(firstErr)) {
          throw firstErr;
        }
        // Retry without strict time window in case the node references an older event.
        body = await http.get('/api/xdr-visualizer/alerts/event', {
          query: {
            ...queryBase,
            hours: 168,
          },
        }) as AlertEventDetailsResponse;
      }
      if (requestSeq !== detailsRequestSeqRef.current) {
        return;
      }
      setSelectedProcessDetails((body as AlertEventDetailsResponse).source || null);
      setSelectedProcessDetailsEventId((body as AlertEventDetailsResponse).eventId || '');
    } catch (err: any) {
      if (requestSeq !== detailsRequestSeqRef.current) {
        return;
      }
      const message = String(err?.body?.message ?? err?.message ?? err);
      setSelectedProcessDetails(null);
      setSelectedProcessDetailsEventId('');
      setProcessDetailsError(message);
    } finally {
      if (requestSeq === detailsRequestSeqRef.current) {
        setLoadingProcessDetails(false);
      }
    }
  }, [http, timeRange.from, timeRange.to, graph]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const hostOptions = useMemo<HostOption[]>(() => {
    const hosts = summary?.byHost ?? [];
    return hosts
      .map((entry) => entry.key)
      .filter((entry) => entry && entry !== 'unknown')
      .map((label) => ({ label }));
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
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const pagedRows = useMemo(
    () => rows.slice(pageIndex * pageSize, pageIndex * pageSize + pageSize),
    [pageIndex, pageSize, rows]
  );
  const selected = rows.find((row) => row.id === selectedAlertId);
  const processTree = useMemo(
    () => (graph ? buildProcessTree(graph.nodes, graph.edges, graph.alertId) : null),
    [graph]
  );

  const closeProcessDetails = useCallback(() => {
    detailsRequestSeqRef.current += 1;
    setSelectedProcessNodeId('');
    setSelectedProcessDetails(null);
    setSelectedProcessDetailsEventId('');
    setProcessDetailsError('');
    setProcessDetailsRequestLabel('');
    setSelectedDetailsKind('process');
    setDetailsViewTab('table');
    setDetailsSearchQuery('');
    setLoadingProcessDetails(false);
  }, []);

  const detailsRows = useMemo(() => toDetailsRows(selectedProcessDetails), [selectedProcessDetails]);
  const filteredDetailsRows = useMemo(() => {
    const query = detailsSearchQuery.trim().toLowerCase();
    if (!query) {
      return detailsRows;
    }
    return detailsRows.filter((row) => row.field.toLowerCase().includes(query) || row.value.toLowerCase().includes(query));
  }, [detailsRows, detailsSearchQuery]);

  // Close popup when graph changes
  useEffect(() => {
    setArtifactPopup(null);
    closeProcessDetails();
  }, [graph]);

  const graphSurface = !loadingGraph && graph && processTree ? (
    <div
      style={{
        width: '100%',
        maxWidth: '100%',
        overflowX: 'auto',
        overflowY: 'auto',
        height: graphFullscreen ? '100%' : undefined,
        maxHeight: graphFullscreen ? '100%' : 560,
        border: '1px solid #d3dae6',
        borderRadius: 8,
        background: '#f9fbfd',
        position: 'relative',
        paddingBottom: graphFullscreen ? 0 : 8,
        cursor: isPanningGraph ? 'grabbing' : 'grab',
        userSelect: 'none',
      }}
      onClick={() => setArtifactPopup(null)}
      onMouseDown={(event) => {
        if (event.button !== 0) {
          return;
        }
        const target = event.currentTarget;
        panStateRef.current = {
          active: true,
          startX: event.clientX,
          startY: event.clientY,
          scrollLeft: target.scrollLeft,
          scrollTop: target.scrollTop,
        };
        setIsPanningGraph(true);
      }}
      onMouseMove={(event) => {
        if (!panStateRef.current.active) {
          return;
        }
        event.preventDefault();
        const target = event.currentTarget;
        const deltaX = event.clientX - panStateRef.current.startX;
        const deltaY = event.clientY - panStateRef.current.startY;
        target.scrollLeft = panStateRef.current.scrollLeft - deltaX;
        target.scrollTop = panStateRef.current.scrollTop - deltaY;
      }}
      onMouseUp={() => {
        panStateRef.current.active = false;
        setIsPanningGraph(false);
      }}
      onMouseLeave={() => {
        panStateRef.current.active = false;
        setIsPanningGraph(false);
      }}
    >
      <svg
        ref={svgRef}
        width={Math.ceil(processTree.width * graphZoom)}
        height={Math.ceil(processTree.height * graphZoom)}
        style={{ display: 'block' }}
      >
        <g transform={`scale(${graphZoom})`}>
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
              <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#0077cc" strokeWidth={2} />
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

        {processTree.treeNodes.map((node) => {
          const pos = processTree.positions.get(node.id);
          if (!pos) {
            return null;
          }
          const alerts = processTree.alertsByProcess.get(node.id) ?? [];
          const artifacts = processTree.artifactsByProcess.get(node.id) ?? [];
          const artifactPopupOpen = artifactPopup?.nodeId === node.id;
          const fileCount = artifacts.filter((a) => a.type === 'file.path' || (a.filePath && !a.module?.includes('library'))).length;
          const libCount = artifacts.filter((a) => a.module?.includes('library')).length;
          const artifactBtnY = pos.y + NODE_H - 16;


          return (
            <g
              key={node.id}
              style={{ cursor: 'pointer' }}
              onClick={(e) => {
                e.stopPropagation();
                void loadProcessDetails({
                  eventId: node.sourceEventId || node.id,
                  processEntityId: node.processEntityId,
                  sourceKind: 'process',
                });
              }}
            >
              <rect
                x={pos.x}
                y={pos.y}
                width={NODE_W}
                height={NODE_H}
                rx={8}
                fill={selectedProcessNodeId === node.id ? '#e8f4fd' : '#fff'}
                stroke={selectedProcessNodeId === node.id ? '#005eb8' : '#0077cc'}
                strokeWidth={selectedProcessNodeId === node.id ? 3 : 2}
              />
              <text x={pos.x + 10} y={pos.y + 16} fill="#0077cc" fontSize="11" fontWeight="bold">
                PROCESS
              </text>
              <text x={pos.x + 10} y={pos.y + 32} fill="#1a1c21" fontSize="11">
                {(node.processName || '').slice(0, 22)}
              </text>
              <text x={pos.x + 10} y={pos.y + 47} fill="#1a1c21" fontSize="10">
                {(node.processCommandLine || '').slice(0, 24)}
              </text>
              <text x={pos.x + 10} y={pos.y + 60} fill="#69707d" fontSize="9">
                {`PID: ${node.processPid ?? '?'}`}
              </text>
              <text x={pos.x + 10} y={pos.y + 73} fill="#69707d" fontSize="9">
                {`PPID: ${node.processPpid ?? '?'}`}
              </text>
              {node.processEntityId && (
                <text x={pos.x + 10} y={pos.y + 86} fill="#98a2b3" fontSize="8">
                  {node.processEntityId}
                </text>
              )}

              {alerts.map((alertNode) => {
                const alertPos = processTree.alertPositions.get(alertNode.id);
                if (!alertPos) {
                  return null;
                }
                const badgeX = alertPos.x;
                const badgeY = alertPos.y;
                return (
                  <g
                    key={alertNode.id}
                    style={{ cursor: 'pointer' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      void loadProcessDetails({
                        eventId: alertNode.id,
                        sourceKind: 'alert',
                      });
                    }}
                  >
                    <line
                      x1={badgeX + NODE_W / 2}
                      y1={badgeY + 11}
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
                      ! {alertNode.label.slice(0, 30)}
                    </text>
                  </g>
                );
              })}

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
                          <text
                            key={art.id}
                            x={popX + 10}
                            y={popY + 28 + artIdx * lineH}
                            fontSize="10"
                            fill="#005eb8"
                            style={{ cursor: 'pointer' }}
                            onClick={() => {
                              void loadProcessDetails({
                                eventId: art.sourceEventId || art.id,
                                processEntityId: art.processEntityId,
                                sourceKind: 'artifact',
                              });
                            }}
                          >
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

        <defs>
          <filter id="shadow" x="-10%" y="-10%" width="120%" height="130%">
            <feDropShadow dx="2" dy="4" stdDeviation="4" floodColor="#00000022" />
          </filter>
        </defs>
        </g>
      </svg>
    </div>
  ) : null;

  useEffect(() => {
    if (pageIndex > 0 && pageIndex >= totalPages) {
      setPageIndex(totalPages - 1);
    }
  }, [pageIndex, totalPages]);

  return (
    <div style={{ padding: 16 }}>
      <style>
        {`.xdrDetailsScrollRegion { scrollbar-width: auto; scrollbar-color: #98a2b3 #e5e7eb; }
          .xdrDetailsScrollRegion::-webkit-scrollbar { width: 12px; height: 12px; }
          .xdrDetailsScrollRegion::-webkit-scrollbar-track { background: #e5e7eb; }
          .xdrDetailsScrollRegion::-webkit-scrollbar-thumb { background: #98a2b3; border-radius: 8px; border: 2px solid #e5e7eb; }
          .xdrDetailsScrollRegion::-webkit-scrollbar-thumb:hover { background: #6b7280; }`}
      </style>
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

      <EuiFlexGroup gutterSize="m" alignItems="stretch" responsive={false}>
        <EuiFlexItem grow={false} style={{ width: 420, minWidth: 420 }}>
          <EuiPanel hasShadow style={{ minHeight: 360, background: '#ffffff' }}>
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
                      width: 180,
                      height: 180,
                      borderRadius: '50%',
                      background: donutBackground(summary),
                      position: 'relative',
                      boxShadow: 'inset 0 0 0 18px rgba(255,255,255,0.95), 0 12px 28px rgba(0,0,0,0.08)',
                    }}
                  >
                    <div
                      style={{
                        position: 'absolute',
                        inset: 46,
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
                <EuiFlexItem grow={false} style={{ minWidth: 170 }}>
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

        <EuiFlexItem grow={true} style={{ minWidth: 0, maxWidth: '100%' }}>
          <EuiPanel hasShadow style={{ minHeight: 360, maxWidth: '100%', overflow: 'hidden' }}>
            <EuiTitle size="s">
              <h2>Recent Alerts</h2>
            </EuiTitle>
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false} wrap>
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
              <EuiFlexItem grow={false} style={{ minWidth: 220 }}>
                <EuiComboBox
                  placeholder="Filter by host"
                  singleSelection={{ asPlainText: true }}
                  options={hostOptions}
                  selectedOptions={hostFilter ? [{ label: hostFilter }] : []}
                  onChange={(selected) => {
                    const next = selected[0]?.label || '';
                    setHostFilter(next);
                  }}
                  isClearable
                  compressed
                />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiToolTip content="Clear severity and host filters">
                  <EuiButton color="text" size="s" onClick={() => { setSeverityFilter(''); setHostFilter(''); }}>
                    Reset filters
                  </EuiButton>
                </EuiToolTip>
              </EuiFlexItem>
            </EuiFlexGroup>
            <EuiSpacer size="s" />
            <div style={{ maxHeight: 280, overflowY: 'auto', overflowX: 'auto' }}>
              <div style={{ minWidth: 980, fontSize: 12 }}>
                <EuiBasicTable<VisualizerAlertItem>
                  compressed
                  items={pagedRows}
                  columns={tableColumns}
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
            <EuiSpacer size="s" />
            <EuiFlexGroup alignItems="center" justifyContent="spaceBetween" gutterSize="s" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiText size="xs" color="subdued">
                  Rows per page: {pageSize}
                </EuiText>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiFlexGroup alignItems="center" gutterSize="s" responsive={false}>
                  <EuiFlexItem grow={false}>
                    <EuiText size="xs" color="subdued">
                      {rows.length === 0 ? 'Page 0 of 0' : `Page ${pageIndex + 1} of ${totalPages}`}
                    </EuiText>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="arrowLeft"
                      aria-label="Previous alerts page"
                      onClick={() => setPageIndex((current) => Math.max(0, current - 1))}
                      isDisabled={pageIndex === 0}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="arrowRight"
                      aria-label="Next alerts page"
                      onClick={() => setPageIndex((current) => Math.min(totalPages - 1, current + 1))}
                      isDisabled={rows.length === 0 || pageIndex >= totalPages - 1}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
              </EuiFlexItem>
            </EuiFlexGroup>
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer size="m" />
      <EuiHorizontalRule margin="m" />

      <EuiPanel hasShadow>
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
                <EuiButtonIcon
                  iconType="minusInCircle"
                  aria-label="Zoom out graph"
                  onClick={() => setGraphZoom((current) => Math.max(0.5, Number((current - 0.1).toFixed(2))))}
                  isDisabled={graphZoom <= 0.5}
                />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiText size="xs" color="subdued">{Math.round(graphZoom * 100)}%</EuiText>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonIcon
                  iconType="plusInCircle"
                  aria-label="Zoom in graph"
                  onClick={() => setGraphZoom((current) => Math.min(2.5, Number((current + 0.1).toFixed(2))))}
                  isDisabled={graphZoom >= 2.5}
                />
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty size="xs" onClick={() => setGraphZoom(1)}>
                  Reset zoom
                </EuiButtonEmpty>
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

        {!loadingGraph && graph && processTree && graphSurface}

        <EuiSpacer size="s" />
        <EuiText size="xs" color="subdued">
          Process nodes are telemetry.process events. Alert boxes are laid out in a dedicated rail and linked to contributing processes. Artifact badges open the related telemetry artifact events and their full source documents.
        </EuiText>
      </EuiPanel>

      {graphFullscreen && graphSurface && (
        <div
          style={{
            position: 'fixed',
            top: 100,
            left: 24,
            right: 24,
            bottom: 24,
            zIndex: 1600,
            background: '#ffffff',
            padding: 16,
            boxShadow: '0 20px 48px rgba(0,0,0,0.18)',
            border: '2px solid #b8c4d6',
            borderRadius: 12,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            boxSizing: 'border-box',
          }}
        >
          <div
            style={{
              width: '100%',
              border: '1px solid #d3dae6',
              borderRadius: 8,
              padding: '4px 8px',
              marginBottom: 8,
              background: 'rgba(255,255,255,0.98)',
            }}
          >
            <EuiFlexGroup gutterSize="s" alignItems="center" justifyContent="spaceBetween" responsive={false}>
              <EuiFlexItem grow={false}>
                <EuiTitle size="xs">
                  <h3>Attack Footprint Graph</h3>
                </EuiTitle>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiFlexGroup gutterSize="s" alignItems="center" responsive={false}>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="minusInCircle"
                      aria-label="Zoom out graph"
                      onClick={() => setGraphZoom((current) => Math.max(0.5, Number((current - 0.1).toFixed(2))))}
                      isDisabled={graphZoom <= 0.5}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiText size="xs" color="subdued">{Math.round(graphZoom * 100)}%</EuiText>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="plusInCircle"
                      aria-label="Zoom in graph"
                      onClick={() => setGraphZoom((current) => Math.min(2.5, Number((current + 0.1).toFixed(2))))}
                      isDisabled={graphZoom >= 2.5}
                    />
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonEmpty size="xs" onClick={() => setGraphZoom(1)}>
                      Reset
                    </EuiButtonEmpty>
                  </EuiFlexItem>
                  <EuiFlexItem grow={false}>
                    <EuiButtonIcon
                      iconType="cross"
                      aria-label="Close full screen graph"
                      onClick={() => setGraphFullscreen(false)}
                    />
                  </EuiFlexItem>
                </EuiFlexGroup>
              </EuiFlexItem>
            </EuiFlexGroup>
          </div>
          <div style={{ flex: 1, minHeight: 0 }}>{graphSurface}</div>
        </div>
      )}

      {(selectedProcessNodeId || loadingProcessDetails || processDetailsError) && (
        <EuiFlyout onClose={closeProcessDetails} ownFocus size="m" style={{ display: 'flex', flexDirection: 'column' }}>
          <EuiFlyoutHeader hasBorder>
            <EuiTitle size="m">
              <h2>
                {selectedDetailsKind === 'alert'
                  ? 'Alert Details'
                  : selectedDetailsKind === 'artifact'
                    ? 'Artifact Event Details'
                    : 'Process Details'}
              </h2>
            </EuiTitle>
            <EuiText size="s" color="subdued">
              <p>
                {selectedDetailsKind === 'alert'
                  ? 'Inspect the full event document for the selected alert badge.'
                  : selectedDetailsKind === 'artifact'
                    ? 'Inspect the full event document for the selected artifact event.'
                    : 'Inspect the full event document for the selected process node.'}
              </p>
            </EuiText>
          </EuiFlyoutHeader>
          <EuiFlyoutBody style={{ display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden', flex: 1 }}>
            {loadingProcessDetails && <EuiLoadingSpinner size="l" />}
            {!loadingProcessDetails && processDetailsError && (
              <EuiCallOut color="warning" size="s" title="Event details unavailable" iconType="alert">
                <p>{processDetailsError}</p>
                {processDetailsRequestLabel && (
                  <p style={{ marginTop: 8 }}>
                    Request: <code>{processDetailsRequestLabel}</code>
                  </p>
                )}
              </EuiCallOut>
            )}
            {!loadingProcessDetails && selectedProcessDetails && (
              <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
                <EuiText size="xs" color="subdued">event.id: {selectedProcessDetailsEventId || selectedProcessNodeId}</EuiText>
                <EuiSpacer size="s" />

                <EuiTabs size="s">
                  <EuiTab
                    onClick={() => setDetailsViewTab('table')}
                    isSelected={detailsViewTab === 'table'}
                  >
                    Table
                  </EuiTab>
                  <EuiTab
                    onClick={() => setDetailsViewTab('json')}
                    isSelected={detailsViewTab === 'json'}
                  >
                    JSON
                  </EuiTab>
                </EuiTabs>

                <EuiSpacer size="s" />

                {detailsViewTab === 'table' && (
                  <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
                    <EuiFieldSearch
                      fullWidth
                      compressed
                      value={detailsSearchQuery}
                      onChange={(event) => setDetailsSearchQuery(event.target.value)}
                      placeholder="Filter fields and values in this event"
                    />
                    <EuiSpacer size="s" />
                    <EuiText size="xs" color="subdued">
                      Showing {filteredDetailsRows.length} of {detailsRows.length} rows
                    </EuiText>
                    <EuiSpacer size="s" />
                    <DetailsScrollPane>
                      <EuiBasicTable<DetailsFieldRow>
                        compressed
                        items={filteredDetailsRows}
                        columns={[
                          {
                            field: 'field',
                            name: 'Field',
                            width: '42%',
                            render: (value: string) => <code>{value}</code>,
                          },
                          {
                            field: 'value',
                            name: 'Value',
                            render: (value: string) => (
                              <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{value}</span>
                            ),
                          },
                        ]}
                      />
                    </DetailsScrollPane>
                  </div>
                )}

                {detailsViewTab === 'json' && (
                  <DetailsScrollPane>
                    <EuiCodeBlock language="json" isCopyable whiteSpace="pre">
                      {prettyJson(selectedProcessDetails)}
                    </EuiCodeBlock>
                  </DetailsScrollPane>
                )}
              </div>
            )}
          </EuiFlyoutBody>
          <EuiFlyoutFooter style={{ flexShrink: 0 }}>
            <EuiButtonEmpty onClick={closeProcessDetails}>Close</EuiButtonEmpty>
          </EuiFlyoutFooter>
        </EuiFlyout>
      )}
    </div>
  );
};
