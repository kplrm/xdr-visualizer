# xdr-visualizer Architecture

## Purpose

`xdr-visualizer` gives analysts a fast workflow from alert volume to attack footprint.

The plugin is intentionally split into two analysis layers.

1. Summary layer: alert counts over time, host/severity pivots, and alert selection.
2. Footprint layer: bounded event graph reconstruction around a selected alert.

## Correlation Inputs

The footprint layer uses:

- `source.event.id` for direct trigger linkage
- `process.entity_id` and `process.parent.entity_id` for lineage pivots
- `file.path` for file-touch pivots

## Data Sources

- Security alerts index pattern: `.xdr-agent-security-*`
- Telemetry index pattern: `.xdr-agent-telemetry-*`

## Correlation Strategy

The server route builds a bounded graph by combining:

- Root alert document.
- Source event id linkage (`source.event.id`).
- Process entity and parent-entity linkage.
- File path linkage.
- Time-window constraints and host scoping.

This keeps response size predictable while preserving useful attack-story context.

## Ownership

- `xdr-agent`: emits telemetry and alerts with lineage fields.
- `xdr-defense`: owns detection/prevention content and rollout contracts.
- `xdr-visualizer`: investigative UI and graph-oriented correlation view.

## Non-Goals

- Policy management and rollout orchestration
- Detection or prevention runtime behavior
- Endpoint enforcement and remediation actions
