const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const ts = require('typescript');
process.env.NODE_PATH = path.join(process.env.OSD_ROOT || path.resolve(__dirname, '../../OpenSearch-Dashboards'), 'node_modules');
require('node:module').Module._initPaths();
require.extensions['.ts'] = (module, filename) => module._compile(ts.transpileModule(readFileSync(filename, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText, filename);

const routes = new Map();
require('../server/routes/alerts.ts').registerAlertRoutes({
  get: (config, handler) => routes.set(config.path, { config, handler }),
});
const alert = {
  _id: 'agent:alert-1', _source: {
    '@timestamp': '2026-10-18T12:00:00Z', 'host.hostname': 'host',
    'event.kind': 'alert', 'event.type': 'alert', 'event.module': 'detection.malware', 'event.severity': 3,
    'rule.id': 'test-rule', 'rule.name': 'Test rule', 'file.path': '/tmp/sample',
    'process.entity_id': 'process-1', 'process.name': 'sample', 'source.event.id': 'agent:process-event',
  },
};
const processEvent = {
  _id: 'agent:process-event', _source: {
    '@timestamp': '2026-10-18T11:59:59Z', 'host.hostname': 'host',
    'event.type': 'process.start', 'event.module': 'telemetry.process',
    process: { entity_id: 'process-1', pid: 42, name: 'sample', executable: '/tmp/sample' },
  },
};
const hits = (...documents) => ({ body: { hits: {
  total: { value: documents.length }, hits: documents,
} } });
async function call(routeName, search, query = {}) {
  const route = routes.get(`/api/xdr-visualizer/alerts/${routeName}`);
  return route.handler({ core: { opensearch: { client: { asInternalUser: { search } } } } }, {
    query: route.config.validate.query.validate(query),
  }, {
    ok: ({ body }) => ({ status: 200, body }),
    customError: ({ statusCode, body }) => ({ status: statusCode, body }),
  });
}

test('alert summaries read root detection fields and aggregate the mapped rule name', async () => {
  const requests = [];
  const result = await call('summary', async request => {
    requests.push(request);
    return hits(alert);
  });
  assert.equal(result.status, 200);
  assert.equal(requests[0].body.aggs.by_rule.terms.field, 'rule.name');
  assert.equal(result.body.recentAlerts[0].ruleId, 'test-rule');
  assert.equal(result.body.recentAlerts[0].ruleName, 'Test rule');
  assert.equal(result.body.recentAlerts[0].processEntityId, 'process-1');
  assert.equal(result.body.recentAlerts[0].filePath, '/tmp/sample');
  assert.equal(result.body.recentAlerts[0].id, 'agent:alert-1');
});

test('event details search mapped process identities directly', async () => {
  let request;
  const result = await call('event', async value => { request = value; return hits(processEvent); }, {
    process_entity_id: 'process-1',
  });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.source, processEvent._source);
  assert.equal(result.body.eventId, processEvent._id);
  assert.deepEqual(request.body.query.bool.should.map(term => Object.keys(term.term)[0]), [
    'process.entity_id', 'process.parent.entity_id', 'process.ancestors.entity_id', 'process.group_leader.entity_id',
  ]);
});

test('event details look up the document metadata ID without adding it to the document', async () => {
  let request;
  const result = await call('event', async value => { request = value; return hits(processEvent); }, {
    event_id: processEvent._id,
  });
  assert.equal(result.status, 200);
  assert.deepEqual(request.body.query.bool.should, [{ term: { _id: processEvent._id } }]);
  assert.deepEqual(result.body.source, processEvent._source);
  assert.equal(result.body.eventId, processEvent._id);
});

test('the investigation graph links root alert context to process and file events', async () => {
  const requests = [];
  const artifact = {
    _id: 'agent:file-event', _source: {
      '@timestamp': alert._source['@timestamp'], 'event.module': 'telemetry.file', 'event.type': 'file.created',
      file: { path: '/tmp/sample' }, process: { entity_id: 'process-1' },
    },
  };
  const result = await call('events', async request => {
    requests.push(request);
    if (request.index === 'xdr-agent-security') return hits(alert);
    if (request.body.size === 500) return hits();
    if (request.body.size === 1200) return hits(artifact);
    return hits(processEvent);
  }, { alert_id: alert._id });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.ok(result.body.nodes.some(node => node.kind === 'process' && node.processEntityId === 'process-1'));
  assert.ok(result.body.nodes.some(node => node.kind === 'alert' && node.label === 'Test rule'));
  assert.ok(result.body.nodes.some(node => node.kind === 'artifact' && node.filePath === '/tmp/sample'));
  assert.ok(result.body.edges.some(edge => edge.relation === 'triggered_by'));
  assert.ok(result.body.nodes.some(node => node.sourceEventId === processEvent._id));
  assert.deepEqual(requests[0].body.query.bool.should, [{ term: { _id: alert._id } }]);
  const triggerLookup = requests.find(request => request.body.query?.bool?.should?.some(term => term.term?._id === processEvent._id));
  assert.ok(triggerLookup, 'alert links must resolve through the full telemetry document ID');
  for (const source of Object.values(result.body.nodeSources)) {
    assert.equal(Object.hasOwn(source, 'id'), false);
    assert.equal(Object.hasOwn(source, '_id'), false);
  }
  assert.doesNotMatch(JSON.stringify(requests), /payload\.|\.keyword/);
});
