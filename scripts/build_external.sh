#!/usr/bin/env bash
# Build against a disposable copy; never stage into the upstream checkout.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_NAME="$(basename "${ROOT_DIR}")"
OSD_SOURCE="${OSD_ROOT:-${ROOT_DIR}/../OpenSearch-Dashboards}"
if [[ ! -f "${OSD_SOURCE}/scripts/plugin_helpers.js" ]]; then
  echo "Dashboards build checkout is unavailable: ${OSD_SOURCE}" >&2
  exit 1
fi
if [[ -f "${ROOT_DIR}/scripts/test_api.cjs" ]]; then node --test "${ROOT_DIR}/scripts/test_api.cjs"; fi
if [[ -f "${ROOT_DIR}/scripts/test_inventory.cjs" ]]; then node --test "${ROOT_DIR}/scripts/test_inventory.cjs"; fi
if [[ -n "${XDR_BUILD_WORKSPACE:-}" ]]; then
  STAGING="${XDR_BUILD_WORKSPACE}"
  mkdir -p "${STAGING}"
else
  STAGING="$(mktemp -d "${TMPDIR:-/tmp}/xdr-plugin-build.XXXXXX")"
  trap 'rm -rf "${STAGING}"' EXIT
fi
BUILD_OSD="${STAGING}/OpenSearch-Dashboards"
mkdir -p "${BUILD_OSD}"
case "$(realpath "${BUILD_OSD}")/" in
  "$(realpath "${OSD_SOURCE}")/"*) echo "Build workspace must be outside the upstream checkout" >&2; exit 1 ;;
esac
if [[ ! -f "${BUILD_OSD}/scripts/plugin_helpers.js" ]]; then
tar -C "${OSD_SOURCE}" --exclude='./.git' --exclude='./plugins' --exclude='./build' --exclude='./target' -cf - . | tar -C "${BUILD_OSD}" -xf -
# The optimizer asks Git for a source revision and changed files.
git -C "${BUILD_OSD}" init -q
git -C "${BUILD_OSD}" add -A
git -C "${BUILD_OSD}" -c core.hooksPath=/dev/null -c user.name='XDR local build' -c user.email='build@localhost' commit -qm 'Disposable build source'
fi
PLUGIN_DIR="${BUILD_OSD}/plugins/${PLUGIN_NAME}"
rm -rf "${PLUGIN_DIR}"
mkdir -p "${PLUGIN_DIR}"
tar -C "${ROOT_DIR}" --exclude='./.git' --exclude='./node_modules' --exclude='./build' --exclude='./target' --exclude='./.yarn' --exclude='./.pnp.*' -cf - . | tar -C "${PLUGIN_DIR}" -xf -
cd "${PLUGIN_DIR}"
node ../../scripts/plugin_helpers build "$@"
mkdir -p "${ROOT_DIR}/build"
cp -f "${PLUGIN_DIR}/build/"*.zip "${ROOT_DIR}/build/"
echo "Built ${PLUGIN_NAME}: ${ROOT_DIR}/build"
