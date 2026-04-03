declare const require: any;

import {
  AlertEventDetailsResponse,
  AlertEventGraphResponse,
  AlertsSummaryResponse,
  EventGraphEdge,
  EventGraphNode,
  VisualizerAlertItem,
} from '../../common';

const { schema } = require('@osd/config-schema');

const SECURITY_INDEX = '.xdr-agent-security-*';
const TELEMETRY_INDEX = '.xdr-agent-telemetry-*';

function scopedClient(ctx: any): any | null {
  if (typeof ctx?.core?.opensearch?.client?.asInternalUser?.search === 'function') {
    return ctx.core.opensearch.client.asInternalUser;
  }
  if (typeof ctx?.opensearch?.client?.asInternalUser?.search === 'function') {
    return ctx.opensearch.client.asInternalUser;
  }
  if (typeof ctx?.core?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.core.opensearch.client.asCurrentUser;
  }
  if (typeof ctx?.opensearch?.client?.asCurrentUser?.search === 'function') {
    return ctx.opensearch.client.asCurrentUser;
  }
  return null;
}

function normalizeSource(hit: any): any {
  return hit?._source ?? {};
}

function payloadFrom(source: any): Record<string, any> {
  const payload = source?.payload;
  if (!payload || typeof payload !== 'object') {
    return {};
  }
  return payload as Record<string, any>;
}

function hasValue(value: unknown): boolean {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  return true;
}

function readPath(target: any, path: string): any {
  if (!target || typeof target !== 'object') {
    return undefined;
  }
  if (hasValue(target[path])) {
    return target[path];
  }
  const parts = path.split('.');
  let current = target;
  for (const part of parts) {
    if (!current || typeof current !== 'object' || !(part in current)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function sourceField(source: any, ...paths: string[]): any {
  for (const path of paths) {
    const value = readPath(source, path);
    if (hasValue(value)) {
      return value;
    }
  }
  return undefined;
}

function payloadField(source: any, ...paths: string[]): any {
  const payload = payloadFrom(source);
  for (const path of paths) {
    const value = readPath(payload, path);
    if (hasValue(value)) {
      return value;
    }
  }
  return undefined;
}

function severityLabel(sev: number): string {
  if (sev >= 9) {
    return 'critical';
  }
  if (sev >= 7) {
    return 'high';
  }
  if (sev >= 4) {
    return 'medium';
  }
  return 'low';
}

function safeString(raw: unknown, fallback = ''): string {
  const value = String(raw ?? '').trim();
  return value || fallback;
}

function uniqueStrings(values: Array<string | undefined>): string[] {
  const unique = new Set<string>();
  for (const value of values) {
    const normalized = safeString(value);
    if (normalized) {
      unique.add(normalized);
    }
  }
  return [...unique];
}

function mapAlert(source: any, fallbackId?: string): VisualizerAlertItem {
  const id = safeString(sourceField(source, 'id'), fallbackId || 'unknown-alert');
  const severity = Number(sourceField(source, 'event.severity') ?? 1);
  return {
    id,
    timestamp: safeString(sourceField(source, '@timestamp')),
    host: safeString(sourceField(source, 'host.hostname'), 'unknown'),
    severity,
    module: safeString(sourceField(source, 'event.module', 'module'), 'unknown'),
    ruleId: safeString(payloadField(source, 'rule.id')) || undefined,
    ruleName: safeString(payloadField(source, 'rule.name')) || undefined,
    action: safeString(payloadField(source, 'event.action')) || undefined,
    sourceModule: safeString(payloadField(source, 'source.module')) || undefined,
    sourceType: safeString(payloadField(source, 'source.type')) || undefined,
    processEntityId: safeString(payloadField(source, 'process.entity_id')) || undefined,
    processName: safeString(payloadField(source, 'process.name')) || undefined,
    processCommandLine: safeString(payloadField(source, 'process.command_line')) || undefined,
    filePath: safeString(payloadField(source, 'file.path', 'process.executable')) || undefined,
  };
}

function buildFilter(hours: number, severity?: string, host?: string, from?: string, to?: string): any[] {
  const filters: any[] = [
    { range: { '@timestamp': { gte: from || `now-${hours}h`, lte: to || 'now' } } },
    { term: { 'event.kind': 'alert' } },
  ];

  if (severity) {
    filters.push({ term: { 'event.severity': severityToValue(severity) } });
  }
  if (host) {
    filters.push({ term: { 'host.hostname': host } });
  }
  return filters;
}

function severityToValue(input: string): number {
  const value = input.toLowerCase();
  if (value === 'critical') {
    return 9;
  }
  if (value === 'high') {
    return 7;
  }
  if (value === 'medium') {
    return 4;
  }
  return 1;
}

function toSeverityBuckets(buckets: Array<{ key: number; doc_count: number }>): Array<{ key: string; count: number }> {
  const map = new Map<string, number>([
    ['critical', 0],
    ['high', 0],
    ['medium', 0],
    ['low', 0],
  ]);

  for (const bucket of buckets) {
    const key = severityLabel(Number(bucket.key));
    map.set(key, (map.get(key) || 0) + Number(bucket.doc_count || 0));
  }

  return ['critical', 'high', 'medium', 'low'].map((key) => ({ key, count: map.get(key) || 0 }));
}

function asBuckets(input: any): Array<{ key: string; count: number }> {
  const buckets = Array.isArray(input?.buckets) ? input.buckets : [];
  return buckets.map((bucket: any) => ({ key: safeString(bucket.key, 'unknown'), count: Number(bucket.doc_count || 0) }));
}

function eventToNode(source: any, fallbackId: string): EventGraphNode {
  const id = safeString(sourceField(source, 'id'), fallbackId);
  const eventKind = safeString(sourceField(source, 'event.kind'));
  const processEntityId = safeString(payloadField(source, 'process.entity_id'));
  const processParentEntityId = safeString(payloadField(source, 'process.parent.entity_id'));
  const processName = safeString(payloadField(source, 'process.name'));
  const processCommandLine = safeString(payloadField(source, 'process.command_line'));
  // Only treat true file/library paths as artifacts; process executable is process metadata.
  const filePath = safeString(payloadField(source, 'file.path', 'dll.path'));
  let kind: EventGraphNode['kind'] = 'event';
  if (eventKind === 'alert') {
    kind = 'alert';
  } else if (processEntityId || processName) {
    kind = 'process';
  } else if (filePath) {
    kind = 'file';
  }

  return {
    id,
    timestamp: safeString(sourceField(source, '@timestamp')),
    label: safeString(
      payloadField(source, 'rule.name')
      || processName
      || filePath
      || sourceField(source, 'event.action')
      || sourceField(source, 'event.type')
      || id,
      id
    ),
    kind,
    sourceEventId: id,
    module: safeString(sourceField(source, 'event.module', 'module')) || undefined,
    type: safeString(sourceField(source, 'event.type')) || undefined,
    host: safeString(sourceField(source, 'host.hostname')) || undefined,
    processEntityId: processEntityId || undefined,
    processParentEntityId: processParentEntityId || undefined,
    processName: processName || undefined,
    processCommandLine: processCommandLine || undefined,
    filePath: filePath || undefined,
  };
}

function uniqueNodes(nodes: EventGraphNode[]): EventGraphNode[] {
  const seen = new Map<string, EventGraphNode>();
  for (const node of nodes) {
    if (!seen.has(node.id)) {
      seen.set(node.id, node);
    }
  }
  return [...seen.values()].sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')));
}

function uniqueEdges(edges: EventGraphEdge[]): EventGraphEdge[] {
  const seen = new Map<string, EventGraphEdge>();
  for (const edge of edges) {
    if (!seen.has(edge.id)) {
      seen.set(edge.id, edge);
    }
  }
  return [...seen.values()];
}

function lineageNodeId(entityId: string): string {
  return `lineage-process-${entityId}`;
}

function buildLineage(source: any, sourceNodeId: string): { nodes: EventGraphNode[]; edges: EventGraphEdge[] } {
  const process = payloadField(source, 'process');
  const parent = process && typeof process === 'object'
    ? readPath(process, 'parent')
    : {
        entity_id: safeString(payloadField(source, 'process.parent.entity_id')),
        name: safeString(payloadField(source, 'process.parent.name')),
        executable: safeString(payloadField(source, 'process.parent.executable')),
        command_line: safeString(payloadField(source, 'process.parent.command_line')),
      };
  const ancestors = process && typeof process === 'object' && Array.isArray(readPath(process, 'ancestors'))
    ? readPath(process, 'ancestors')
    : [];

  if ((!parent || typeof parent !== 'object' || !safeString(readPath(parent, 'entity_id'))) && ancestors.length === 0) {
    return { nodes: [], edges: [] };
  }
  const orderedAncestors: any[] = [];
  const seenEntities = new Set<string>();

  const pushAncestor = (entry: any) => {
    const entityId = safeString(readPath(entry, 'entity_id'));
    if (!entityId || seenEntities.has(entityId)) {
      return;
    }
    seenEntities.add(entityId);
    orderedAncestors.push(entry);
  };

  if (parent && typeof parent === 'object') {
    pushAncestor(parent);
  }
  for (const ancestor of ancestors) {
    if (ancestor && typeof ancestor === 'object') {
      pushAncestor(ancestor);
    }
  }

  const nodes: EventGraphNode[] = [];
  const edges: EventGraphEdge[] = [];
  let childId = sourceNodeId;

  for (const ancestor of orderedAncestors) {
    const entityId = safeString(readPath(ancestor, 'entity_id'));
    if (!entityId) {
      continue;
    }
    const nodeId = lineageNodeId(entityId);
    nodes.push({
      id: nodeId,
      timestamp: safeString(sourceField(source, '@timestamp')) || undefined,
      label: safeString(readPath(ancestor, 'name') || readPath(ancestor, 'executable') || entityId, entityId),
      kind: 'process',
      sourceEventId: undefined,
      module: 'process.lineage',
      type: 'ancestor',
      host: safeString(sourceField(source, 'host.hostname')) || undefined,
      processEntityId: entityId,
      processName: safeString(readPath(ancestor, 'name')) || undefined,
      processCommandLine: safeString(readPath(ancestor, 'command_line')) || undefined,
      filePath: undefined,
    });
    edges.push({
      id: `parent-${nodeId}-${childId}`,
      from: nodeId,
      to: childId,
      relation: 'parent_of',
    });
    childId = nodeId;
  }

  return { nodes, edges };
}

function buildFileArtifacts(nodes: EventGraphNode[]): { nodes: EventGraphNode[]; edges: EventGraphEdge[] } {
  const createdNodes: EventGraphNode[] = [];
  const edges: EventGraphEdge[] = [];
  const fileNodeByPath = new Map<string, string>();
  const processNodeByEntityId = new Map<string, EventGraphNode>();

  for (const node of nodes) {
    if (node.kind === 'process' && node.processEntityId && !processNodeByEntityId.has(node.processEntityId)) {
      processNodeByEntityId.set(node.processEntityId, node);
    }
    if (node.kind === 'file' && node.filePath) {
      fileNodeByPath.set(node.filePath, node.id);
    }
  }

  for (const node of nodes) {
    // Only file-bearing event/file nodes create file artifacts.
    if (!node.filePath || (node.kind !== 'event' && node.kind !== 'file')) {
      continue;
    }

    let fileNodeId = fileNodeByPath.get(node.filePath);
    if (!fileNodeId) {
      fileNodeId = `file-artifact-${node.filePath}`;
      fileNodeByPath.set(node.filePath, fileNodeId);
      createdNodes.push({
        id: fileNodeId,
        timestamp: node.timestamp,
        label: node.filePath,
        kind: 'file',
        module: 'artifact.file',
        type: 'file.path',
        host: node.host,
        filePath: node.filePath,
      });
    }

    const owningProcessNode = node.processEntityId ? processNodeByEntityId.get(node.processEntityId) : undefined;
    const fromNodeId = owningProcessNode?.id || node.id;

    if (fileNodeId !== fromNodeId) {
      edges.push({
        id: `touch-${fromNodeId}-${fileNodeId}`,
        from: fromNodeId,
        to: fileNodeId,
        relation: 'touches',
      });
    }
  }

  return { nodes: createdNodes, edges };
}

function buildEdges(nodes: EventGraphNode[], sourceEventId: string): EventGraphEdge[] {
  const edges: EventGraphEdge[] = [];
  const byProcess = new Map<string, EventGraphNode[]>();
  const byParent = new Map<string, EventGraphNode[]>();
  const sorted = [...nodes].sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')));

  for (const node of sorted) {
    if (node.processEntityId) {
      const arr = byProcess.get(node.processEntityId) ?? [];
      arr.push(node);
      byProcess.set(node.processEntityId, arr);
    }
    if (node.processParentEntityId) {
      const arr = byParent.get(node.processParentEntityId) ?? [];
      arr.push(node);
      byParent.set(node.processParentEntityId, arr);
    }
  }

  const alertNode = sorted.find((node) => node.kind === 'alert');
  if (alertNode) {
    const src = sorted.find((node) => node.id === sourceEventId)
      || sorted.find((node) => node.id !== alertNode.id && node.processEntityId && node.processEntityId === alertNode.processEntityId);
    if (src) {
      edges.push({
        id: `triggered-${alertNode.id}-${src.id}`,
        from: alertNode.id,
        to: src.id,
        relation: 'triggered_by',
      });
    }
  }

  for (const [entityId, parents] of byProcess.entries()) {
    const children = byParent.get(entityId) ?? [];
    for (const parentNode of parents) {
      for (const childNode of children) {
        if (parentNode.id !== childNode.id) {
          edges.push({
            id: `parent-${parentNode.id}-${childNode.id}`,
            from: parentNode.id,
            to: childNode.id,
            relation: 'parent_of',
          });
        }
      }
    }
  }

  const temporalNodes = sorted.filter((node) => node.kind !== 'file' && node.module !== 'process.lineage');
  for (let idx = 0; idx < temporalNodes.length - 1; idx += 1) {
    const current = temporalNodes[idx];
    const next = temporalNodes[idx + 1];
    edges.push({
      id: `time-${current.id}-${next.id}`,
      from: current.id,
      to: next.id,
      relation: 'temporal',
    });
  }

  return uniqueEdges(edges);
}

function termFilters(fields: string[], values: string[]): any[] {
  const filters: any[] = [];
  for (const value of values) {
    for (const field of fields) {
      filters.push({ term: { [field]: value } });
    }
  }
  return filters;
}

export function registerAlertRoutes(router: any): void {
  router.get(
    {
      path: '/api/xdr-visualizer/alerts/summary',
      validate: {
        query: schema.object({
          hours: schema.maybe(schema.number({ min: 1, max: 168 })),
          from: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
          to: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
          severity: schema.maybe(schema.string({ minLength: 1, maxLength: 16 })),
          host: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
        }),
      },
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedClient(ctx);
        if (!client) {
          return res.customError({
            statusCode: 503,
            body: { message: 'OpenSearch client unavailable.' },
          });
        }

        const hours = Number(req.query?.hours ?? 24);
        const from = req.query?.from ? String(req.query.from) : undefined;
        const to = req.query?.to ? String(req.query.to) : undefined;
        const severity = req.query?.severity ? String(req.query.severity).toLowerCase() : undefined;
        const host = req.query?.host ? String(req.query.host).trim() : undefined;

        const queryFilter = buildFilter(hours, severity, host, from, to);

        const [summaryResult, alertsResult] = await Promise.all([
          client.search({
            index: SECURITY_INDEX,
            allow_no_indices: true,
            ignore_unavailable: true,
            body: {
              size: 0,
              query: { bool: { filter: queryFilter } },
              aggs: {
                by_severity: { terms: { field: 'event.severity', size: 10 } },
                by_rule: { terms: { field: 'payload.rule.name', size: 8 } },
                by_host: { terms: { field: 'host.hostname', size: 8 } },
              },
            },
          }),
          client.search({
            index: SECURITY_INDEX,
            allow_no_indices: true,
            ignore_unavailable: true,
            body: {
              size: 200,
              sort: [{ '@timestamp': { order: 'desc' } }],
              query: { bool: { filter: queryFilter } },
            },
          }),
        ]);

        const total = Number(summaryResult?.body?.hits?.total?.value ?? 0);
        const severityBuckets = toSeverityBuckets(summaryResult?.body?.aggregations?.by_severity?.buckets ?? []);
        const byRule = asBuckets(summaryResult?.body?.aggregations?.by_rule);
        const byHost = asBuckets(summaryResult?.body?.aggregations?.by_host);

        const hits = Array.isArray(alertsResult?.body?.hits?.hits) ? alertsResult.body.hits.hits : [];
        const recentAlerts = hits.map((hit: any) => mapAlert(normalizeSource(hit), safeString(hit?._id, '')));

        const body: AlertsSummaryResponse = {
          total,
          bySeverity: severityBuckets,
          byRule,
          byHost,
          recentAlerts,
        };

        return res.ok({ body });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: { message: String(err?.message ?? err) },
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-visualizer/alerts/events',
      validate: {
        query: schema.object({
          alert_id: schema.string({ minLength: 3, maxLength: 1024 }),
          hours: schema.maybe(schema.number({ min: 1, max: 168 })),
          from: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
          to: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
        }),
      },
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedClient(ctx);
        if (!client) {
          return res.customError({
            statusCode: 503,
            body: { message: 'OpenSearch client unavailable.' },
          });
        }

        const alertId = String(req.query.alert_id);
        const hours = Number(req.query.hours ?? 24);
        const from = req.query?.from ? String(req.query.from) : undefined;
        const to = req.query?.to ? String(req.query.to) : undefined;

        const alertResult = await client.search({
          index: SECURITY_INDEX,
          allow_no_indices: true,
          ignore_unavailable: true,
          body: {
            size: 1,
            query: {
              bool: {
                should: [
                  { term: { 'id.keyword': alertId } },
                  { term: { id: alertId } },
                  { term: { _id: alertId } },
                ],
                minimum_should_match: 1,
              },
            },
          },
        });

        const alertHits = Array.isArray(alertResult?.body?.hits?.hits) ? alertResult.body.hits.hits : [];
        if (alertHits.length === 0) {
          const empty: AlertEventGraphResponse = { alertId, nodes: [], edges: [] };
          return res.ok({ body: empty });
        }

        const alertHit = alertHits[0];
        const source = normalizeSource(alertHit);

        const host = safeString(sourceField(source, 'host.hostname'));
        const sourceEventId = safeString(payloadField(source, 'source.event.id'));
        const processEntityId = safeString(payloadField(source, 'process.entity_id'));
        const processParentEntityId = safeString(payloadField(source, 'process.parent.entity_id'));
        const relevantPaths = uniqueStrings([
          safeString(payloadField(source, 'file.path')),
          safeString(payloadField(source, 'process.executable')),
        ]);

        const relatedResult = await client.search({
          index: `${SECURITY_INDEX},${TELEMETRY_INDEX}`,
          allow_no_indices: true,
          ignore_unavailable: true,
          body: {
            size: 500,
            sort: [{ '@timestamp': { order: 'asc' } }],
            query: {
              bool: {
                filter: [
                  { range: { '@timestamp': { gte: from || `now-${hours}h`, lte: to || 'now' } } },
                  ...(host ? [{ term: { 'host.hostname': host } }] : []),
                ],
                should: [
                  ...(sourceEventId ? [{ term: { 'id.keyword': sourceEventId } }, { term: { id: sourceEventId } }, { term: { _id: sourceEventId } }] : []),
                  ...termFilters(['payload.process.entity_id', 'payload.process.entity_id.keyword'], uniqueStrings([processEntityId, processParentEntityId])),
                  ...termFilters(['payload.process.parent.entity_id', 'payload.process.parent.entity_id.keyword'], uniqueStrings([processEntityId, processParentEntityId])),
                  ...termFilters(['payload.file.path', 'payload.file.path.keyword', 'payload.process.executable', 'payload.process.executable.keyword'], relevantPaths),
                ],
                minimum_should_match: 1,
              },
            },
          },
        });

        const relatedHits = Array.isArray(relatedResult?.body?.hits?.hits) ? relatedResult.body.hits.hits : [];
        const sourceTelemetryHit = relatedHits.find((hit: any) => safeString(normalizeSource(hit)?.id) === sourceEventId);
        const alertNode = eventToNode(source, safeString(alertHit?._id, alertId));
        const relatedNodes = relatedHits.map((hit: any) => eventToNode(normalizeSource(hit), safeString(hit?._id, '')));
        const lineage = buildLineage(sourceTelemetryHit ? normalizeSource(sourceTelemetryHit) : source, sourceEventId || alertNode.id);
        const baseNodes = uniqueNodes([alertNode, ...relatedNodes, ...lineage.nodes]);
        const fileArtifacts = buildFileArtifacts(baseNodes);
        const nodes = uniqueNodes([...baseNodes, ...fileArtifacts.nodes]);
        const edges = uniqueEdges([...lineage.edges, ...fileArtifacts.edges, ...buildEdges(nodes, sourceEventId)]);

        const body: AlertEventGraphResponse = {
          alertId: alertNode.id,
          nodes,
          edges,
        };

        return res.ok({ body });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: { message: String(err?.message ?? err) },
        });
      }
    }
  );

  router.get(
    {
      path: '/api/xdr-visualizer/alerts/event',
      validate: {
        query: schema.object({
          event_id: schema.maybe(schema.string({ minLength: 1, maxLength: 2048 })),
          process_entity_id: schema.maybe(schema.string({ minLength: 1, maxLength: 2048 })),
          hours: schema.maybe(schema.number({ min: 1, max: 168 })),
          from: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
          to: schema.maybe(schema.string({ minLength: 1, maxLength: 128 })),
        }),
      },
    },
    async (ctx: any, req: any, res: any) => {
      try {
        const client = scopedClient(ctx);
        if (!client) {
          return res.customError({
            statusCode: 503,
            body: { message: 'OpenSearch client unavailable.' },
          });
        }

        const eventId = req.query?.event_id ? String(req.query.event_id) : '';
        const processEntityId = req.query?.process_entity_id ? String(req.query.process_entity_id) : '';
        const hours = Number(req.query.hours ?? 24);
        const from = req.query?.from ? String(req.query.from) : undefined;
        const to = req.query?.to ? String(req.query.to) : undefined;

        if (!eventId && !processEntityId) {
          return res.customError({
            statusCode: 400,
            body: { message: 'Either event_id or process_entity_id is required.' },
          });
        }

        const should: any[] = [];
        if (eventId) {
          should.push({ term: { 'id.keyword': eventId } }, { term: { id: eventId } }, { term: { _id: eventId } });
        }
        if (processEntityId) {
          should.push(
            { term: { 'payload.process.entity_id.keyword': processEntityId } },
            { term: { 'payload.process.entity_id': processEntityId } },
            { term: { 'payload.process.parent.entity_id.keyword': processEntityId } },
            { term: { 'payload.process.parent.entity_id': processEntityId } },
            { term: { 'payload.process.ancestors.entity_id.keyword': processEntityId } },
            { term: { 'payload.process.ancestors.entity_id': processEntityId } },
            { term: { 'payload.process.group_leader.entity_id.keyword': processEntityId } },
            { term: { 'payload.process.group_leader.entity_id': processEntityId } },
            { term: { 'process.entity_id.keyword': processEntityId } },
            { term: { 'process.entity_id': processEntityId } }
          );
        }

        const detailResult = await client.search({
          index: `${SECURITY_INDEX},${TELEMETRY_INDEX}`,
          allow_no_indices: true,
          ignore_unavailable: true,
          body: {
            size: 1,
            sort: [{ '@timestamp': { order: 'desc' } }],
            query: {
              bool: {
                filter: [{ range: { '@timestamp': { gte: from || `now-${hours}h`, lte: to || 'now' } } }],
                should,
                minimum_should_match: 1,
              },
            },
          },
        });

        const hit = Array.isArray(detailResult?.body?.hits?.hits) ? detailResult.body.hits.hits[0] : undefined;
        if (!hit) {
          const identifier = eventId || processEntityId;
          return res.customError({ statusCode: 404, body: { message: `Event not found: ${identifier}` } });
        }

        const body: AlertEventDetailsResponse = {
          eventId: safeString(normalizeSource(hit)?.id, eventId || processEntityId),
          source: normalizeSource(hit),
        };
        return res.ok({ body });
      } catch (err: any) {
        return res.customError({
          statusCode: 500,
          body: { message: String(err?.message ?? err) },
        });
      }
    }
  );
}
