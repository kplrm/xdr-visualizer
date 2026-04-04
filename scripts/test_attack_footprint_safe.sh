#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "This script must run as root. Example: sudo bash xdr-visualizer/scripts/test_attack_footprint_safe.sh" >&2
    exit 1
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required" >&2
    exit 1
  }
}

require_root
require_cmd curl
require_cmd jq
require_cmd sha256sum
require_cmd cp
require_cmd chmod
require_cmd systemctl

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
OSD_URL="${OSD_URL:-http://localhost:5601}"
SECURITY_INDEX="${SECURITY_INDEX:-.xdr-agent-security-*}"
TELEMETRY_INDEX="${TELEMETRY_INDEX:-.xdr-agent-telemetry-*}"
SERVICE_NAME="${SERVICE_NAME:-xdr-agent}"
SEARCH_TIMEOUT_SECONDS="${SEARCH_TIMEOUT_SECONDS:-60}"
SEARCH_POLL_SECONDS="${SEARCH_POLL_SECONDS:-5}"
START_WAIT_SECONDS="${START_WAIT_SECONDS:-8}"
POST_ALERT_WAIT_SECONDS="${POST_ALERT_WAIT_SECONDS:-8}"
RUN_ROOT="${RUN_ROOT:-/var/tmp}"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_ID="xdr-viz-graph-safe-${RUN_TS}"
SCRIPT_START_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

SCENARIO_DIR="${RUN_ROOT%/}/${RUN_ID}"
TRIGGER_BIN="/dev/shm/xdr-viz-graph-safe-${RUN_TS}.bin"
RULE_NAME="xdr_visualizer_graph_hash_${RUN_TS}"
CUSTOM_HASH_ID=""
MEMORY_RULE_ID="${MEMORY_RULE_ID:-capa-memory-dev-shm-exec}"

ALERT_ID=""
SOURCE_EVENT_ID=""
TRIGGER_PID=""

cleanup() {
  local code=$?
  trap - EXIT INT TERM

  if [[ -n "${CUSTOM_HASH_ID}" ]]; then
    curl -sS -X DELETE "${OSD_URL%/}/api/xdr-defense/hashes/rules/${CUSTOM_HASH_ID}" -H 'osd-xsrf: true' >/dev/null 2>&1 || true
  fi
  rm -f "${TRIGGER_BIN}" >/dev/null 2>&1 || true
  rm -rf "${SCENARIO_DIR}" >/dev/null 2>&1 || true

  systemctl restart "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
  exit "$code"
}
trap cleanup EXIT INT TERM

mkdir -p "${SCENARIO_DIR}"

log "Preparing unique trigger executable"
cp /usr/bin/bash "${TRIGGER_BIN}"
chmod 700 "${TRIGGER_BIN}"
printf '\nXDR_VIZ_HASH_MARKER_%s\n' "${RUN_TS}" >>"${TRIGGER_BIN}"
TRIGGER_SHA256="$(sha256sum "${TRIGGER_BIN}" | awk '{print $1}')"

log "Verifying trigger binary can execute from ${SCENARIO_DIR}"
if ! probe_err="$("${TRIGGER_BIN}" -c 'exit 0' 2>&1)"; then
  log "ERROR: trigger binary failed to execute from ${SCENARIO_DIR}"
  echo "${probe_err}" >&2
  exit 1
fi

log "Installing temporary hash IOC ${RULE_NAME}"
create_hash_payload="$(cat <<EOF_HASH
{
  "name": "${RULE_NAME}",
  "sha256_hash": "${TRIGGER_SHA256}",
  "enabled": true,
  "severity": "critical",
  "tags": ["xdr-visualizer-safe-test", "temporary"]
}
EOF_HASH
)"
create_hash_result="$(curl -sS -X POST "${OSD_URL%/}/api/xdr-defense/hashes/rules" -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d "${create_hash_payload}")"
CUSTOM_HASH_ID="$(jq -r '.id // empty' <<<"${create_hash_result}" 2>/dev/null || true)"
if [[ -z "${CUSTOM_HASH_ID}" ]]; then
  log "ERROR: failed to create temporary custom hash rule via xdr-defense API"
  echo "${create_hash_result}" >&2
  exit 1
fi
log "Custom hash rule created with id: ${CUSTOM_HASH_ID}"

log "Waiting ${START_WAIT_SECONDS}s for hash reload ticker"
sleep "${START_WAIT_SECONDS}"

log "Executing safe attack-footprint scenario"
# The copied bash binary is the hash trigger process. It modifies files, then spawns child commands.
"${TRIGGER_BIN}" -c '
set -euo pipefail
base="$1"
echo "alpha" >"$base/doc-a.txt"
echo "beta" >"$base/doc-b.txt"
cat "$base/doc-a.txt" >>"$base/doc-b.txt"
/usr/bin/touch "$base/doc-c.txt"
/usr/bin/sh -c "echo child-one >> \"$base/doc-c.txt\""
/usr/bin/sed -i "s/alpha/gamma/" "$base/doc-b.txt"
/usr/bin/find "$base" -maxdepth 1 -type f -print >/dev/null
/usr/bin/wc -c "$base/doc-b.txt" >/dev/null
/usr/bin/sleep 2
# Keep a builtin as the last command so bash does not exec() the final external command.
:
' _ "${SCENARIO_DIR}" >"${SCENARIO_DIR}/trigger.stdout.log" 2>"${SCENARIO_DIR}/trigger.stderr.log" &
TRIGGER_PID=$!
if ! wait "${TRIGGER_PID}"; then
  log "ERROR: trigger scenario process exited non-zero"
  if [[ -s "${SCENARIO_DIR}/trigger.stderr.log" ]]; then
    tail -n 30 "${SCENARIO_DIR}/trigger.stderr.log" >&2 || true
  fi
  exit 1
fi

log "Polling for security alert tied to temporary hash"
elapsed=0
while (( elapsed <= SEARCH_TIMEOUT_SECONDS )); do
  search_body="$(cat <<EOF_ALERT_SEARCH
{
  "size": 1,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"term": {"event.kind": "alert"}},
        {"range": {"@timestamp": {"gte": "${SCRIPT_START_UTC}"}}}
      ],
      "should": [
        {
          "bool": {
            "must": [
              {"match_phrase": {"payload.rule.id": "malware.hash.match"}},
              {"match_phrase": {"payload.rule.name": "${RULE_NAME}"}},
              {"match_phrase": {"payload.file.path": "${TRIGGER_BIN}"}},
              {"match_phrase": {"payload.source.module": "telemetry.process"}}
            ]
          }
        },
        {
          "bool": {
            "must": [
              {"match_phrase": {"payload.rule.id": "${MEMORY_RULE_ID}"}},
              {"match_phrase": {"payload.process.command_line": "${SCENARIO_DIR}"}},
              {"match_phrase": {"payload.source.module": "telemetry.process"}}
            ]
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
EOF_ALERT_SEARCH
)"

  result="$(curl -sS -X POST "${OPENSEARCH_URL%/}/${SECURITY_INDEX}/_search?ignore_unavailable=true&allow_no_indices=true" -H 'Content-Type: application/json' -d "${search_body}")"
  hit_count="$(jq -r '.hits.hits | length' <<<"${result}" 2>/dev/null || echo 0)"

  if [[ "${hit_count}" =~ ^[0-9]+$ ]] && (( hit_count > 0 )); then
    ALERT_ID="$(jq -r '.hits.hits[0]._id' <<<"${result}")"
    SOURCE_EVENT_ID="$(jq -r '.hits.hits[0]._source.payload["source.event.id"] // ""' <<<"${result}")"
    break
  fi

  log "No matching alert yet (elapsed=${elapsed}s)"
  sleep "${SEARCH_POLL_SECONDS}"
  elapsed=$((elapsed + SEARCH_POLL_SECONDS))
done

if [[ -z "${ALERT_ID}" ]]; then
  log "ERROR: no hash alert found for this run"
  exit 1
fi

log "Alert found; waiting ${POST_ALERT_WAIT_SECONDS}s for telemetry/graph indexing"
sleep "${POST_ALERT_WAIT_SECONDS}"

log "Querying visualizer attack-footprint graph"
graph_json="$(curl -sS "${OSD_URL%/}/api/xdr-visualizer/alerts/events?alert_id=${ALERT_ID}&from=now-30m&to=now" -H 'osd-xsrf: true')"

if ! jq -e '.nodes and .edges' >/dev/null <<<"${graph_json}"; then
  log "ERROR: visualizer graph response missing nodes/edges"
  echo "Raw response:" >&2
  echo "${graph_json}" >&2
  exit 1
fi

node_count="$(jq -r '.nodes | length' <<<"${graph_json}")"
edge_count="$(jq -r '.edges | length' <<<"${graph_json}")"
process_count="$(jq -r '[.nodes[] | select(.kind=="process")] | length' <<<"${graph_json}")"
artifact_count="$(jq -r '[.nodes[] | select(.kind=="artifact")] | length' <<<"${graph_json}")"

log "Inspecting telemetry evidence for modified files and spawned commands"
telemetry_body="$(cat <<EOF_TEL
{
  "size": 100,
  "sort": [{"@timestamp": {"order": "asc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "${SCRIPT_START_UTC}"}}},
        {
          "bool": {
            "should": [
              {"query_string": {"query": "${SCENARIO_DIR}"}},
              {"match_phrase": {"payload.process.executable": "${TRIGGER_BIN}"}},
              {"match_phrase": {"payload.process.command_line": "${SCENARIO_DIR}"}},
              {"term": {"id.keyword": "${SOURCE_EVENT_ID}"}},
              {"term": {"id": "${SOURCE_EVENT_ID}"}},
              {"term": {"_id": "${SOURCE_EVENT_ID}"}}
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
EOF_TEL
)"
telemetry_json="$(curl -sS -X POST "${OPENSEARCH_URL%/}/${TELEMETRY_INDEX}/_search?ignore_unavailable=true&allow_no_indices=true" -H 'Content-Type: application/json' -d "${telemetry_body}")"
telemetry_hits="$(jq -r '.hits.hits | length' <<<"${telemetry_json}" 2>/dev/null || echo 0)"
telemetry_elapsed=0
while [[ "${telemetry_hits}" =~ ^[0-9]+$ ]] && (( telemetry_hits == 0 )) && (( telemetry_elapsed < 20 )); do
  sleep 5
  telemetry_elapsed=$((telemetry_elapsed + 5))
  telemetry_json="$(curl -sS -X POST "${OPENSEARCH_URL%/}/${TELEMETRY_INDEX}/_search?ignore_unavailable=true&allow_no_indices=true" -H 'Content-Type: application/json' -d "${telemetry_body}")"
  telemetry_hits="$(jq -r '.hits.hits | length' <<<"${telemetry_json}" 2>/dev/null || echo 0)"
done

if [[ "${telemetry_hits}" =~ ^[0-9]+$ ]] && (( telemetry_hits == 0 )) && [[ -n "${SOURCE_EVENT_ID}" ]]; then
  telemetry_ids_body="$(cat <<EOF_TEL_IDS
{
  "size": 20,
  "query": {
    "ids": {
      "values": ["${SOURCE_EVENT_ID}"]
    }
  }
}
EOF_TEL_IDS
)"
  telemetry_json="$(curl -sS -X POST "${OPENSEARCH_URL%/}/${TELEMETRY_INDEX}/_search?ignore_unavailable=true&allow_no_indices=true" -H 'Content-Type: application/json' -d "${telemetry_ids_body}")"
  telemetry_hits="$(jq -r '.hits.hits | length' <<<"${telemetry_json}" 2>/dev/null || echo 0)"
fi

security_body="$(cat <<EOF_SEC
{
  "size": 20,
  "sort": [{"@timestamp": {"order": "asc"}}],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "${SCRIPT_START_UTC}"}}},
        {"term": {"event.kind": "alert"}},
        {"match_phrase": {"payload.rule.name": "${RULE_NAME}"}}
      ]
    }
  }
}
EOF_SEC
)"
security_json="$(curl -sS -X POST "${OPENSEARCH_URL%/}/${SECURITY_INDEX}/_search?ignore_unavailable=true&allow_no_indices=true" -H 'Content-Type: application/json' -d "${security_body}")"
security_hits="$(jq -r '.hits.hits | length' <<<"${security_json}" 2>/dev/null || echo 0)"

printf '\n=== XDR Visualizer Attack-Footprint Safe Test ===\n'
echo "Run ID: ${RUN_ID}"
echo "Start UTC: ${SCRIPT_START_UTC}"
echo "Scenario dir: ${SCENARIO_DIR}"
echo "Trigger binary: ${TRIGGER_BIN}"
echo "Temporary custom hash id: ${CUSTOM_HASH_ID}"
echo "Rule name (hash): ${RULE_NAME}"
echo "Memory fallback rule id: ${MEMORY_RULE_ID}"
echo "Alert ID: ${ALERT_ID}"
echo "Source event ID: ${SOURCE_EVENT_ID}"
echo ""
echo "Visualizer graph: nodes=${node_count} edges=${edge_count} process_nodes=${process_count} artifact_nodes=${artifact_count}"
echo "Security alerts found (run-scoped): ${security_hits}"
echo "Telemetry events found (run-scoped): ${telemetry_hits}"
echo ""
echo "Sample graph process nodes:"
jq -r '.nodes[] | select(.kind=="process") | "- \(.id) | \(.label) | pid=\(.processPid // "na") ppid=\(.processPpid // "na")"' <<<"${graph_json}" | head -n 12
echo ""
echo "Sample telemetry events touching scenario artifacts:"
jq -r '.hits.hits[] | "- \(._source["@timestamp"] // "") | \(._source["event.type"] // "") | \(._source["event.module"] // "") | \(._source.payload["file.path"] // ._source.payload.process.executable // "")"' <<<"${telemetry_json}" | head -n 20

echo ""
echo "Sample security alerts from this run:"
jq -r '.hits.hits[] | "- \(._source["@timestamp"] // "") | \(._id) | \(._source.payload["rule.id"] // "") | \(._source.payload["file.path"] // "")"' <<<"${security_json}" | head -n 20

if [[ ! "${artifact_count}" =~ ^[0-9]+$ ]] || (( artifact_count == 0 )); then
  log "WARNING: graph has zero artifact nodes; verify file event collection is enabled"
fi

if [[ ! "${telemetry_hits}" =~ ^[0-9]+$ ]] || (( telemetry_hits == 0 )); then
  log "ERROR: no telemetry documents found for scenario"
  exit 1
fi

if [[ ! "${security_hits}" =~ ^[0-9]+$ ]] || (( security_hits == 0 )); then
  log "ERROR: no security alert documents found for scenario"
  exit 1
fi

log "Success: safe scenario produced alert + telemetry and attack-footprint graph response"
