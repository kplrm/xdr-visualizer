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
const MAX_CHAIN_ENTITIES = 40;
const MAX_EVENT_IDS_FOR_ALERT_LINK = 120;

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

function eventId(source: any, fallbackId: string): string {
  return safeString(sourceField(source, 'id'), fallbackId);
}

function eventTimestamp(source: any): string | undefined {
  return safeString(sourceField(source, '@timestamp')) || undefined;
}

function eventModule(source: any): string {
  return safeString(sourceField(source, 'event.module', 'module'));
}

function processEntity(source: any): string {
  return safeString(payloadField(source, 'process.entity_id', 'process.entity.id', 'entity_id', 'entity.id'));
}

function processParentEntity(source: any): string {
  return safeString(payloadField(source, 'process.parent.entity_id', 'process.parent.entity.id', 'parent.entity_id', 'parent.entity.id'));
}

function processName(source: any): string {
  return safeString(payloadField(source, 'process.name', 'process.executable'));
}

function processCommandLine(source: any): string {
  return safeString(payloadField(source, 'process.command_line', 'process.cmdline', 'process.executable'));
}

function processPid(source: any): number | undefined {
  const raw = payloadField(source, 'process.pid', 'pid');
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : undefined;
}

function processPpid(source: any): number | undefined {
  const raw = payloadField(source, 'process.ppid', 'process.parent.pid', 'ppid');
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : undefined;
}

function processNodeFromTelemetry(source: any, fallbackId: string): EventGraphNode {
  const id = eventId(source, fallbackId);
  const entityId = processEntity(source);
  const parentEntityId = processParentEntity(source);
  const name = processName(source);
  const cmd = processCommandLine(source);
  const label = safeString(name || cmd || entityId || id, id);
  return {
    id,
    timestamp: eventTimestamp(source),
    label,
    kind: 'process',
    sourceEventId: id,
    module: eventModule(source) || undefined,
    type: safeString(sourceField(source, 'event.type')) || undefined,
    host: safeString(sourceField(source, 'host.hostname')) || undefined,
    processEntityId: entityId || undefined,
    processParentEntityId: parentEntityId || undefined,
    processPid: processPid(source),
    processPpid: processPpid(source),
    processName: name || undefined,
    processCommandLine: cmd || undefined,
  };
}

function alertNodeFromSource(source: any, fallbackId: string): EventGraphNode {
  const id = eventId(source, fallbackId);
  const entityId = processEntity(source);
  const parentEntityId = processParentEntity(source);
  return {
    id,
    timestamp: eventTimestamp(source),
    label: safeString(payloadField(source, 'rule.name') || payloadField(source, 'rule.id') || sourceField(source, 'event.action') || id, id),
    kind: 'alert',
    sourceEventId: id,
    module: eventModule(source) || undefined,
    type: safeString(sourceField(source, 'event.type')) || undefined,
    host: safeString(sourceField(source, 'host.hostname')) || undefined,
    processEntityId: entityId || undefined,
    processParentEntityId: parentEntityId || undefined,
    processName: processName(source) || undefined,
    processCommandLine: processCommandLine(source) || undefined,
    filePath: safeString(payloadField(source, 'file.path')) || undefined,
  };
}

interface ArtifactRef {
  value: string;
  type: string;
}

function artifactRef(source: any): ArtifactRef | null {
  const candidates: Array<{ path: string; type: string }> = [
    { path: 'file.path', type: 'file.path' },
    { path: 'dll.path', type: 'library.path' },
    { path: 'library.path', type: 'library.path' },
    { path: 'module.path', type: 'library.path' },
    { path: 'registry.path', type: 'registry.path' },
    { path: 'registry.key', type: 'registry.key' },
    { path: 'socket.path', type: 'ipc.socket.path' },
    { path: 'pipe.path', type: 'ipc.pipe.path' },
    { path: 'target.path', type: 'target.path' },
    { path: 'path', type: 'path' },
  ];

  for (const entry of candidates) {
    const value = safeString(payloadField(source, entry.path) || sourceField(source, entry.path));
    if (value) {
      return { value, type: entry.type };
    }
  }
  return null;
}

function artifactNodeFromSource(source: any, fallbackId: string, artifact: ArtifactRef): EventGraphNode {
  const id = eventId(source, fallbackId);
  return {
    id,
    timestamp: eventTimestamp(source),
    label: artifact.value,
    kind: 'artifact',
    sourceEventId: id,
    module: eventModule(source) || undefined,
    type: artifact.type,
    host: safeString(sourceField(source, 'host.hostname')) || undefined,
    processEntityId: processEntity(source) || undefined,
    processParentEntityId: processParentEntity(source) || undefined,
    processName: processName(source) || undefined,
    processCommandLine: processCommandLine(source) || undefined,
    filePath: artifact.value,
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

function termsShould(filters: Array<{ fields: string[]; values: string[] }>): any[] {
  const should: any[] = [];
  for (const filter of filters) {
    const values = uniqueStrings(filter.values);
    if (values.length === 0) {
      continue;
    }
    for (const field of filter.fields) {
      should.push({ terms: { [field]: values } });
    }
  }
  return should;
}

function chunkStrings(values: string[], chunkSize: number): string[][] {
  const chunks: string[][] = [];
  for (let idx = 0; idx < values.length; idx += chunkSize) {
    chunks.push(values.slice(idx, idx + chunkSize));
  }
  return chunks;
}

function toMillis(ts?: string): number {
  if (!ts) {
    return Number.POSITIVE_INFINITY;
  }
  const value = Date.parse(ts);
  return Number.isFinite(value) ? value : Number.POSITIVE_INFINITY;
}

function pickNearestParent(candidates: EventGraphNode[], child: EventGraphNode): EventGraphNode {
  const childTs = toMillis(child.timestamp);
  let best = candidates[0];
  let bestScore = Number.POSITIVE_INFINITY;
  for (const candidate of candidates) {
    const parentTs = toMillis(candidate.timestamp);
    const delta = parentTs <= childTs ? (childTs - parentTs) : (parentTs - childTs + 10_000_000_000);
    if (delta < bestScore) {
      best = candidate;
      bestScore = delta;
    }
  }
  return best;
}

function sortedByTime<T extends EventGraphNode>(nodes: T[]): T[] {
  return [...nodes].sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')));
}

function lineageNodeId(entityId: string): string {
  return `lineage-process-${entityId}`;
}

function buildAncestorLineage(triggerSource: any, triggerNode: EventGraphNode): { nodes: EventGraphNode[]; edges: EventGraphEdge[] } {
  const payloadProcess = payloadField(triggerSource, 'process');
  const directParent = payloadProcess && typeof payloadProcess === 'object'
    ? readPath(payloadProcess, 'parent')
    : undefined;
  const ancestors = payloadProcess && typeof payloadProcess === 'object' && Array.isArray(readPath(payloadProcess, 'ancestors'))
    ? (readPath(payloadProcess, 'ancestors') as any[])
    : [];

  const ordered: any[] = [];
  const seen = new Set<string>();
  const pushEntry = (entry: any) => {
    if (!entry || typeof entry !== 'object') {
      return;
    }
    const entityId = safeString(readPath(entry, 'entity_id'));
    if (!entityId || seen.has(entityId)) {
      return;
    }
    seen.add(entityId);
    ordered.push(entry);
  };

  pushEntry(directParent);
  for (const anc of ancestors) {
    pushEntry(anc);
  }

  const nodes: EventGraphNode[] = [];
  const edges: EventGraphEdge[] = [];
  let childNodeId = triggerNode.id;
  let childEntity = triggerNode.processEntityId;

  for (const anc of ordered) {
    const entityId = safeString(readPath(anc, 'entity_id'));
    if (!entityId) {
      continue;
    }
    const nodeId = lineageNodeId(entityId);
    nodes.push({
      id: nodeId,
      timestamp: triggerNode.timestamp,
      label: safeString(readPath(anc, 'name') || readPath(anc, 'executable') || entityId, entityId),
      kind: 'process',
      sourceEventId: triggerNode.sourceEventId,
      module: 'telemetry.process.lineage',
      type: 'ancestor',
      host: triggerNode.host,
      processEntityId: entityId,
      processParentEntityId: childEntity,
      processPid: Number(readPath(anc, 'pid')) || undefined,
      processPpid: Number(readPath(anc, 'ppid')) || undefined,
      processName: safeString(readPath(anc, 'name')) || undefined,
      processCommandLine: safeString(readPath(anc, 'command_line') || readPath(anc, 'executable')) || undefined,
    });
    edges.push({
      id: `parent-${nodeId}-${childNodeId}`,
      from: nodeId,
      to: childNodeId,
      relation: 'parent_of',
    });
    childNodeId = nodeId;
    childEntity = entityId;
  }

  return { nodes, edges };
}

function isProcessStartEvent(source: any): boolean {
  return safeString(sourceField(source, 'event.type')) === 'process.start'
    || safeString(payloadField(source, 'source.type')) === 'process.start';
}

function pickRepresentativeProcessSource(events: any[]): any | null {
  if (events.length === 0) {
    return null;
  }
  const sorted = [...events].sort((a, b) => String(eventTimestamp(a) || '').localeCompare(String(eventTimestamp(b) || '')));
  const start = sorted.find((source) => isProcessStartEvent(source));
  return start || sorted[0];
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

        const runSearch = async (stage: string, params: any): Promise<any> => {
          try {
            return await client.search(params);
          } catch (err: any) {
            throw new Error(`[alerts.events:${stage}] ${String(err?.message ?? err)}`);
          }
        };

        const alertResult = await runSearch('alert_lookup', {
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
        const timeFilter = { range: { '@timestamp': { gte: from || `now-${hours}h`, lte: to || 'now' } } };
        const alertTs = Date.parse(safeString(sourceField(source, '@timestamp')));
        const lineageTimeFilter = Number.isFinite(alertTs)
          ? {
              range: {
                '@timestamp': {
                  gte: new Date(alertTs - 30 * 60 * 1000).toISOString(),
                  lte: new Date(alertTs + 30 * 60 * 1000).toISOString(),
                },
              },
            }
          : timeFilter;

        let triggerTelemetrySource: any | null = null;
        if (sourceEventId) {
          const sourceResult = await runSearch('trigger_lookup', {
            index: TELEMETRY_INDEX,
            allow_no_indices: true,
            ignore_unavailable: true,
            body: {
              size: 1,
              query: {
                bool: {
                  filter: [
                    timeFilter,
                    { term: { 'event.module': 'telemetry.process' } },
                    ...(host ? [{ term: { 'host.hostname': host } }] : []),
                  ],
                  should: [{ term: { 'id.keyword': sourceEventId } }, { term: { id: sourceEventId } }, { term: { _id: sourceEventId } }],
                  minimum_should_match: 1,
                },
              },
            },
          });
          const triggerHits = Array.isArray(sourceResult?.body?.hits?.hits) ? sourceResult.body.hits.hits : [];
          if (triggerHits.length > 0) {
            triggerTelemetrySource = normalizeSource(triggerHits[0]);
          }
        }

        if (!triggerTelemetrySource && processEntityId) {
          const fallbackResult = await runSearch('trigger_fallback', {
            index: TELEMETRY_INDEX,
            allow_no_indices: true,
            ignore_unavailable: true,
            body: {
              size: 1,
              sort: [{ '@timestamp': { order: 'desc' } }],
              query: {
                bool: {
                  filter: [
                    timeFilter,
                    { term: { 'event.module': 'telemetry.process' } },
                    ...(host ? [{ term: { 'host.hostname': host } }] : []),
                  ],
                  should: termsShould([
                    {
                      fields: ['payload.process.entity_id.keyword', 'process.entity_id.keyword'],
                      values: [processEntityId],
                    },
                  ]),
                  minimum_should_match: 1,
                },
              },
            },
          });
          const fallbackHits = Array.isArray(fallbackResult?.body?.hits?.hits) ? fallbackResult.body.hits.hits : [];
          if (fallbackHits.length > 0) {
            triggerTelemetrySource = normalizeSource(fallbackHits[0]);
          }
        }

        const seedEntity = safeString(processEntity(triggerTelemetrySource) || processEntityId);
        if (!seedEntity) {
          const selectedAlertNodeOnly = alertNodeFromSource(source, safeString(alertHit?._id, alertId));
          const body: AlertEventGraphResponse = {
            alertId,
            nodes: [selectedAlertNodeOnly],
            edges: [],
          };
          return res.ok({ body });
        }

        const processHitsByEntity = new Map<string, any[]>();

        const pushProcessSource = (processSource: any) => {
          const entity = processEntity(processSource);
          if (!entity) {
            return;
          }
          if (!processHitsByEntity.has(entity) && processHitsByEntity.size >= MAX_CHAIN_ENTITIES) {
            return;
          }
          const arr = processHitsByEntity.get(entity) ?? [];
          const sourceId = eventId(processSource, '');
          if (!sourceId || !arr.some((entry) => eventId(entry, '') === sourceId)) {
            arr.push(processSource);
            processHitsByEntity.set(entity, arr);
          }
        };

        const loadProcessEvents = async (stage: string, matchFields: string[], values: string[], size = 400): Promise<any[]> => {
          const normalizedValues = uniqueStrings(values);
          if (normalizedValues.length === 0) {
            return [];
          }
          const byEventId = new Map<string, any>();
          const chunks = chunkStrings(normalizedValues, 20);

          for (const field of matchFields) {
            for (let chunkIdx = 0; chunkIdx < chunks.length; chunkIdx += 1) {
              const chunk = chunks[chunkIdx];
              const result = await runSearch(`${stage}:${field}:${chunkIdx}`, {
                index: TELEMETRY_INDEX,
                allow_no_indices: true,
                ignore_unavailable: true,
                body: {
                  size,
                  sort: [{ '@timestamp': { order: 'asc' } }],
                  query: {
                    bool: {
                      filter: [
                        lineageTimeFilter,
                        { term: { 'event.module': 'telemetry.process' } },
                        ...(host ? [{ term: { 'host.hostname': host } }] : []),
                        { terms: { [field]: chunk } },
                      ],
                    },
                  },
                },
              });
              const hits = Array.isArray(result?.body?.hits?.hits) ? result.body.hits.hits : [];
              for (const hit of hits) {
                const processSource = normalizeSource(hit);
                const id = eventId(processSource, safeString(hit?._id, ''));
                if (!id || byEventId.has(id)) {
                  continue;
                }
                byEventId.set(id, processSource);
                if (byEventId.size >= size) {
                  break;
                }
              }
              if (byEventId.size >= size) {
                break;
              }
            }
            if (byEventId.size >= size) {
              break;
            }
          }

          return [...byEventId.values()].sort((a, b) => String(eventTimestamp(a) || '').localeCompare(String(eventTimestamp(b) || '')));
        };

        if (triggerTelemetrySource) {
          pushProcessSource(triggerTelemetrySource);
        }

        // Ascend lineage: recursively include direct parents of the seed chain.
        let upFrontier = [seedEntity];
        const seenUp = new Set<string>(upFrontier);
        for (let depth = 0; depth < 6 && upFrontier.length > 0 && processHitsByEntity.size < MAX_CHAIN_ENTITIES; depth += 1) {
          const events = await loadProcessEvents(
            `lineage_up_d${depth}`,
            ['payload.process.entity_id.keyword', 'process.entity_id.keyword', 'payload.process.entity_id', 'process.entity_id'],
            upFrontier,
            300
          );
          const nextUp = new Set<string>();
          const upSet = new Set(upFrontier);
          for (const processSource of events) {
            const entity = processEntity(processSource);
            if (!upSet.has(entity)) {
              continue;
            }
            pushProcessSource(processSource);
            const parentEntity = processParentEntity(processSource);
            if (parentEntity && !seenUp.has(parentEntity)) {
              seenUp.add(parentEntity);
              nextUp.add(parentEntity);
            }
          }
          upFrontier = [...nextUp].slice(0, 24);
        }

        // Descend lineage: recursively include direct children of already-related nodes.
        let downFrontier = [seedEntity];
        const seenDown = new Set<string>(downFrontier);
        for (let depth = 0; depth < 6 && downFrontier.length > 0 && processHitsByEntity.size < MAX_CHAIN_ENTITIES; depth += 1) {
          const events = await loadProcessEvents(
            `lineage_down_d${depth}`,
            ['payload.process.parent.entity_id.keyword', 'process.parent.entity_id.keyword', 'payload.process.parent.entity_id', 'process.parent.entity_id'],
            downFrontier,
            500
          );
          const nextDown = new Set<string>();
          const downSet = new Set(downFrontier);
          for (const processSource of events) {
            const parentEntity = processParentEntity(processSource);
            const childEntity = processEntity(processSource);
            if (!childEntity || !downSet.has(parentEntity)) {
              continue;
            }
            pushProcessSource(processSource);
            if (!seenDown.has(childEntity)) {
              seenDown.add(childEntity);
              nextDown.add(childEntity);
            }
          }
          downFrontier = [...nextDown].slice(0, 40);
        }

        const rawProcessNodes: EventGraphNode[] = [];
        const processNodeBySourceEventId = new Map<string, EventGraphNode>();
        for (const [entity, sources] of processHitsByEntity.entries()) {
          const representative = pickRepresentativeProcessSource(sources);
          if (!representative) {
            continue;
          }
          const node = processNodeFromTelemetry(representative, entity);
          if (!node.processEntityId) {
            node.processEntityId = entity;
          }
          rawProcessNodes.push(node);
          for (const sourceDoc of sources) {
            const sourceId = eventId(sourceDoc, '');
            if (sourceId) {
              processNodeBySourceEventId.set(sourceId, node);
            }
          }
        }

        const processNodes = uniqueNodes(rawProcessNodes);
        const processNodeById = new Map(processNodes.map((node) => [node.id, node]));

        const processNodesByEntity = new Map<string, EventGraphNode[]>();
        const processNodesByPid = new Map<number, EventGraphNode[]>();
        for (const processNode of processNodes) {
          if (processNode.processEntityId) {
            const arr = processNodesByEntity.get(processNode.processEntityId) ?? [];
            arr.push(processNode);
            processNodesByEntity.set(processNode.processEntityId, arr);
          }
          if (processNode.processPid) {
            const arr = processNodesByPid.get(processNode.processPid) ?? [];
            arr.push(processNode);
            processNodesByPid.set(processNode.processPid, arr);
          }
        }
        for (const [entity, nodesForEntity] of processNodesByEntity.entries()) {
          processNodesByEntity.set(entity, sortedByTime(nodesForEntity));
        }
        for (const [pid, nodesForPid] of processNodesByPid.entries()) {
          processNodesByPid.set(pid, sortedByTime(nodesForPid));
        }

        const processEntityIds = uniqueStrings(processNodes.map((node) => node.processEntityId)).slice(0, MAX_CHAIN_ENTITIES);
        const processSourceEventIds = uniqueStrings(
          [...processHitsByEntity.values()].flatMap((sources) => sources.map((sourceDoc: any) => eventId(sourceDoc, '')))
        ).slice(0, MAX_EVENT_IDS_FOR_ALERT_LINK);

        const relatedAlertsResult = processEntityIds.length > 0
          ? await runSearch('related_alerts', {
              index: SECURITY_INDEX,
              allow_no_indices: true,
              ignore_unavailable: true,
              body: {
                size: 400,
                sort: [{ '@timestamp': { order: 'asc' } }],
                query: {
                  bool: {
                    filter: [timeFilter, { term: { 'event.kind': 'alert' } }, ...(host ? [{ term: { 'host.hostname': host } }] : [])],
                    should: termsShould([
                      {
                        fields: ['payload.process.entity_id.keyword'],
                        values: processEntityIds,
                      },
                      {
                        fields: ['payload.process.parent.entity_id.keyword'],
                        values: processEntityIds,
                      },
                      {
                        fields: ['payload.source.event.id.keyword'],
                        values: processSourceEventIds,
                      },
                    ]),
                    minimum_should_match: 1,
                  },
                },
              },
            })
          : null;

        const relatedAlertHits = Array.isArray(relatedAlertsResult?.body?.hits?.hits) ? relatedAlertsResult?.body?.hits?.hits : [];
        const selectedAlertNode = alertNodeFromSource(source, safeString(alertHit?._id, alertId));
        const relatedAlertNodes = relatedAlertHits.map((hit: any) => alertNodeFromSource(normalizeSource(hit), safeString(hit?._id, '')));
        const alertNodes = uniqueNodes([selectedAlertNode, ...relatedAlertNodes]);

        const artifactResult = processEntityIds.length > 0
          ? await runSearch('artifact_events', {
              index: TELEMETRY_INDEX,
              allow_no_indices: true,
              ignore_unavailable: true,
              body: {
                size: 1200,
                sort: [{ '@timestamp': { order: 'asc' } }],
                query: {
                  bool: {
                    filter: [
                      timeFilter,
                      ...(host ? [{ term: { 'host.hostname': host } }] : []),
                      { prefix: { 'event.module': 'telemetry.' } },
                    ],
                    must_not: [{ term: { 'event.module': 'telemetry.process' } }],
                    should: termsShould([
                      {
                        fields: ['payload.process.entity_id.keyword', 'process.entity_id.keyword'],
                        values: processEntityIds,
                      },
                      {
                        fields: ['payload.process.parent.entity_id.keyword', 'process.parent.entity_id.keyword'],
                        values: processEntityIds,
                      },
                    ]),
                    minimum_should_match: 1,
                  },
                },
              },
            })
          : null;

        const artifactHits = Array.isArray(artifactResult?.body?.hits?.hits) ? artifactResult.body.hits.hits : [];
        const artifactNodes = uniqueNodes(
          artifactHits
            .map((hit: any) => ({ source: normalizeSource(hit), fallbackId: safeString(hit?._id, '') }))
            .map(({ source: artifactSource, fallbackId }) => {
              const ref = artifactRef(artifactSource);
              if (!ref) {
                return null;
              }
              return artifactNodeFromSource(artifactSource, fallbackId, ref);
            })
            .filter((node: EventGraphNode | null): node is EventGraphNode => Boolean(node))
        );

        const edges: EventGraphEdge[] = [];

        for (const child of processNodes) {
          let candidateParents: EventGraphNode[] = [];
          if (child.processParentEntityId) {
            candidateParents = processNodesByEntity.get(child.processParentEntityId) ?? [];
          }
          if (candidateParents.length === 0 && child.processPpid) {
            candidateParents = processNodesByPid.get(child.processPpid) ?? [];
          }
          if (candidateParents.length === 0) {
            continue;
          }
          const parent = pickNearestParent(candidateParents, child);
          if (parent.id === child.id) {
            continue;
          }
          edges.push({
            id: `parent-${parent.id}-${child.id}`,
            from: parent.id,
            to: child.id,
            relation: 'parent_of',
          });
        }

        const alertSourcesById = new Map<string, any>();
        alertSourcesById.set(selectedAlertNode.id, source);
        for (const hit of relatedAlertHits) {
          const hitSource = normalizeSource(hit);
          const id = eventId(hitSource, safeString(hit?._id, ''));
          if (id) {
            alertSourcesById.set(id, hitSource);
          }
        }

        for (const alertNode of alertNodes) {
          const alertSource = alertSourcesById.get(alertNode.id);
          const linkedBySourceEventId = safeString(payloadField(alertSource, 'source.event.id'));
          let targetNode: EventGraphNode | undefined;

          if (linkedBySourceEventId) {
            targetNode = processNodeBySourceEventId.get(linkedBySourceEventId) || processNodeById.get(linkedBySourceEventId);
          }

          if (!targetNode && alertNode.processEntityId) {
            const candidates = processNodesByEntity.get(alertNode.processEntityId) ?? [];
            if (candidates.length > 0) {
              targetNode = pickNearestParent(candidates, alertNode);
            }
          }

          if (targetNode) {
            edges.push({
              id: `triggered-${alertNode.id}-${targetNode.id}`,
              from: alertNode.id,
              to: targetNode.id,
              relation: 'triggered_by',
            });
          }
        }

        for (const artifactNode of artifactNodes) {
          const candidateEntity = artifactNode.processEntityId || artifactNode.processParentEntityId;
          if (!candidateEntity) {
            continue;
          }
          const candidates = processNodesByEntity.get(candidateEntity) ?? [];
          if (candidates.length === 0) {
            continue;
          }
          const owner = pickNearestParent(candidates, artifactNode);
          edges.push({
            id: `touch-${owner.id}-${artifactNode.id}`,
            from: owner.id,
            to: artifactNode.id,
            relation: 'touches',
          });
        }

        const triggerProcessNode = processNodes.find((node) => node.sourceEventId === sourceEventId)
          || processNodes.find((node) => node.processEntityId && node.processEntityId === seedEntity)
          || processNodes[0];

        let ancestorLineageNodes: EventGraphNode[] = [];
        let ancestorLineageEdges: EventGraphEdge[] = [];
        if (triggerTelemetrySource && triggerProcessNode) {
          const lineage = buildAncestorLineage(triggerTelemetrySource, triggerProcessNode);
          const existingProcessNodeByEntity = new Map<string, EventGraphNode>();
          for (const processNode of processNodes) {
            if (!processNode.processEntityId || existingProcessNodeByEntity.has(processNode.processEntityId)) {
              continue;
            }
            existingProcessNodeByEntity.set(processNode.processEntityId, processNode);
          }

          const lineageNodeToCanonicalNode = new Map<string, string>();
          ancestorLineageNodes = [];
          for (const lineageNode of lineage.nodes) {
            const entityId = lineageNode.processEntityId || '';
            const existing = entityId ? existingProcessNodeByEntity.get(entityId) : undefined;
            if (existing) {
              // Rewire lineage edges through the real process node when we already have it.
              lineageNodeToCanonicalNode.set(lineageNode.id, existing.id);
              continue;
            }
            ancestorLineageNodes.push(lineageNode);
          }

          const validNodeIds = new Set<string>([
            ...processNodes.map((node) => node.id),
            ...ancestorLineageNodes.map((node) => node.id),
          ]);
          ancestorLineageEdges = uniqueEdges(
            lineage.edges
              .map((edge) => ({
                ...edge,
                from: lineageNodeToCanonicalNode.get(edge.from) || edge.from,
                to: lineageNodeToCanonicalNode.get(edge.to) || edge.to,
              }))
              .filter((edge) => edge.from !== edge.to)
              .filter((edge) => validNodeIds.has(edge.from) && validNodeIds.has(edge.to))
          );

          for (const lineNode of ancestorLineageNodes) {
            if (lineNode.sourceEventId && triggerTelemetrySource) {
              processNodeBySourceEventId.set(lineNode.sourceEventId, triggerProcessNode);
            }
          }
        }

        const allProcessNodes = uniqueNodes([...processNodes, ...ancestorLineageNodes]);
        const allParentEdges = uniqueEdges([
          ...edges.filter((edge) => edge.relation === 'parent_of'),
          ...ancestorLineageEdges,
        ]);

        const connectedProcessNodeIds = new Set<string>();
        if (triggerProcessNode) {
          const adjacency = new Map<string, Set<string>>();
          for (const edge of allParentEdges) {
            const a = adjacency.get(edge.from) ?? new Set<string>();
            a.add(edge.to);
            adjacency.set(edge.from, a);
            const b = adjacency.get(edge.to) ?? new Set<string>();
            b.add(edge.from);
            adjacency.set(edge.to, b);
          }
          const queue: string[] = [triggerProcessNode.id];
          connectedProcessNodeIds.add(triggerProcessNode.id);
          while (queue.length > 0) {
            const current = queue.shift() as string;
            const neighbors = adjacency.get(current) ?? new Set<string>();
            for (const next of neighbors) {
              if (connectedProcessNodeIds.has(next)) {
                continue;
              }
              connectedProcessNodeIds.add(next);
              queue.push(next);
            }
          }
        } else {
          for (const node of allProcessNodes) {
            connectedProcessNodeIds.add(node.id);
          }
        }

        const filteredProcessNodes = allProcessNodes.filter((node) => connectedProcessNodeIds.has(node.id));
        const filteredParentEdges = allParentEdges.filter((edge) => connectedProcessNodeIds.has(edge.from) && connectedProcessNodeIds.has(edge.to));

        const nonParentEdges = edges.filter((edge) => edge.relation !== 'parent_of');
        const filteredNonParentEdges = nonParentEdges.filter((edge) => {
          if (edge.relation === 'triggered_by') {
            return connectedProcessNodeIds.has(edge.to);
          }
          if (edge.relation === 'touches') {
            return connectedProcessNodeIds.has(edge.from);
          }
          return false;
        });

        const finalEdges = uniqueEdges([...filteredParentEdges, ...filteredNonParentEdges]);
        const includedNodeIds = new Set<string>();
        for (const node of filteredProcessNodes) {
          includedNodeIds.add(node.id);
        }
        for (const edge of finalEdges) {
          includedNodeIds.add(edge.from);
          includedNodeIds.add(edge.to);
        }
        includedNodeIds.add(selectedAlertNode.id);

        const nodes = uniqueNodes([...filteredProcessNodes, ...alertNodes, ...artifactNodes].filter((node) => includedNodeIds.has(node.id)));

        const nodeSources: Record<string, Record<string, any>> = {};
        for (const [nodeId, src] of alertSourcesById.entries()) {
          if (src && typeof src === 'object') {
            nodeSources[nodeId] = src as Record<string, any>;
          }
        }
        for (const node of processNodes) {
          if (node.sourceEventId) {
            const src = [...processHitsByEntity.values()].flat().find((doc: any) => eventId(doc, '') === node.sourceEventId);
            if (src && typeof src === 'object') {
              nodeSources[node.sourceEventId] = src as Record<string, any>;
            }
          }
        }
        if (triggerTelemetrySource && triggerProcessNode?.sourceEventId) {
          nodeSources[triggerProcessNode.sourceEventId] = triggerTelemetrySource as Record<string, any>;
        }
        for (const node of ancestorLineageNodes) {
          if (node.sourceEventId && triggerTelemetrySource && typeof triggerTelemetrySource === 'object') {
            nodeSources[node.sourceEventId] = triggerTelemetrySource as Record<string, any>;
          }
        }
        for (const hit of artifactHits) {
          const src = normalizeSource(hit);
          const id = eventId(src, safeString(hit?._id, ''));
          if (id && src && typeof src === 'object') {
            nodeSources[id] = src as Record<string, any>;
          }
        }

        const body: AlertEventGraphResponse = {
          alertId,
          nodes,
          edges: finalEdges,
          nodeSources,
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
