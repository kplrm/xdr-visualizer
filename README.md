# xdr-visualizer

`xdr-visualizer` is an OpenSearch Dashboards investigation plugin for alert triage and attack-footprint analysis.

It provides:

- A high-level alert summary over a selectable time window.
- Interactive filtering by severity and host.
- A correlated event graph that links alerts to source events, process lineage, and file-touch artifacts.
- Full-screen graph analysis mode for deep investigations.

## Scope

`xdr-visualizer` owns investigation UI only.

Out of scope:

- policy authoring or rollout workflows
- detection/prevention runtime execution
- endpoint-side enforcement logic

It consumes indexed data from:

- `.xdr-agent-security-*`
- `.xdr-agent-telemetry-*`

## Main Routes

- `GET /api/xdr-visualizer/alerts/summary`
- `GET /api/xdr-visualizer/alerts/events`

## Build

```bash
cd /home/kplrm/github/xdr-visualizer
yarn build --opensearch-dashboards-version 3.5.0
```
