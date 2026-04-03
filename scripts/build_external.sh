#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OSD_ROOT="${ROOT_DIR}/../OpenSearch-Dashboards"
PLUGIN_DIR="${OSD_ROOT}/plugins/xdr-visualizer"

if [[ ! -d "${OSD_ROOT}" ]]; then
  echo "OpenSearch-Dashboards repo not found at ${OSD_ROOT}" >&2
  exit 1
fi

mkdir -p "${OSD_ROOT}/plugins"
rm -rf "${PLUGIN_DIR}"
cp -a "${ROOT_DIR}" "${PLUGIN_DIR}"
rm -rf "${PLUGIN_DIR}/node_modules" "${PLUGIN_DIR}/build" "${PLUGIN_DIR}/.git"

cd "${PLUGIN_DIR}"
node ../../scripts/plugin_helpers build "$@"

mkdir -p "${ROOT_DIR}/build"
cp -f "${PLUGIN_DIR}/build"/*.zip "${ROOT_DIR}/build/"

echo "External build complete: copied zip to ${ROOT_DIR}/build"
