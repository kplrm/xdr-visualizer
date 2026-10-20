# Contributing to xdr-visualizer

This repository owns alert triage and investigation UI. Start with the [README](README.md) and [investigation architecture](docs/architecture.md). Agent runtime enforcement and Coordinator policy management belong in their respective repositories.

## Development and validation

Use the Node.js version and dependency tooling required by your target OpenSearch Dashboards checkout. Install plugin dependencies with the committed Yarn lockfile where needed. Point `OSD_ROOT` at a bootstrapped checkout matching your deployment:

```bash
export OSD_ROOT=/path/to/bootstrapped/OpenSearch-Dashboards
npm test
npm run build
```

The build targets the version of `OSD_ROOT` by default. An explicit `--opensearch-dashboards-version` must match that checkout. The build uses disposable staging; keep the upstream checkout untouched.

For UI changes, inspect representative alerts and telemetry in Dashboards. Check summaries, host/severity filters, alert selection, graph expansion, and full-screen behavior. Include screenshots for visible changes. End-to-end footprint scenarios that require a running Agent belong in a disposable Linux lab.

## Engineering expectations

- Keep alert searches and graph reconstruction scoped by the relevant host and time window.
- Preserve process lineage, file correlations, and document identity when building graph nodes and edges.
- Bound search and graph growth; handle missing lineage, sparse telemetry, empty results, and partial data.
- Add focused route/correlation regression coverage when behavior changes.
- Match existing TypeScript and React conventions and keep investigation behavior documented in the architecture file.

## Issues and pull requests

Use this repository's [issue tracker](https://github.com/kplrm/xdr-visualizer/issues) for general questions, reproducible bugs, and proposals. Discuss substantial changes before implementation.

1. Fork the repository and branch from `main`.
2. Keep the change focused and follow the existing code style.
3. Add regression coverage for changed behavior and update affected documentation.
4. In your PR, explain the problem, resulting behavior, validation performed, and compatibility impact. List any checks you could not run, including the reason.

Use sanitized logs and fixtures; remove secrets and identifying customer data before posting.

## License and attribution

By submitting a contribution, you agree to license your original changes under the [GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0`). You retain copyright in your contributions. Submit only work you have the right to contribute, and preserve existing copyright and third-party license notices.

## Security reports

Report vulnerabilities through this repository's [private vulnerability reporting](https://github.com/kplrm/xdr-visualizer/security/advisories/new) when enabled. Include affected versions, reproduction steps, impact, and sanitized supporting details. Keep vulnerability, bypass, and credential details out of public issues.

If private reporting is unavailable, open an issue asking the maintainer for a private reporting channel without describing the vulnerability.

## Conduct

Be respectful, direct, and technically concrete in issues, reviews, and discussions.
