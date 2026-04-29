#!/usr/bin/env bash
set -euo pipefail

hub_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_root="$(cd "${hub_root}/.." && pwd)"
contract_dir="${PORTAL_HUB_CONTRACT_DIR:-${hub_root}/contracts/portal-hub/v2}"
portal_root="${PORTAL_DESKTOP_REPO:-${workspace_root}/portal}"
android_root="${PORTAL_ANDROID_REPO:-${workspace_root}/portal-android}"

echo "Checking Portal Hub Android pairing and vault enrollment lifecycle"
(cd "${hub_root}" && cargo test android_vault_pairing_flow_smoke)

if [[ -d "${portal_root}" ]]; then
  echo "Checking Portal desktop vault approval compatibility"
  (
    cd "${portal_root}"
    PORTAL_HUB_CONTRACT_DIR="${contract_dir}" cargo test portal_hub --lib
  )
else
  echo "Skipping Portal desktop; not found at ${portal_root}" >&2
fi

if [[ -d "${android_root}" ]]; then
  echo "Checking Portal Android pairing and vault contract compatibility"
  if command -v java >/dev/null 2>&1; then
    (
      cd "${android_root}"
      PORTAL_HUB_CONTRACT_DIR="${contract_dir}" \
        ./gradlew testOssDebugUnitTest \
          --tests org.connectbot.portal.PortalHubRepositoryTest \
          --tests org.connectbot.portal.PortalHubContractTest
    )
  elif command -v nix >/dev/null 2>&1 && [[ -f "${android_root}/flake.nix" ]]; then
    (
      cd "${android_root}"
      PORTAL_HUB_CONTRACT_DIR="${contract_dir}" \
        nix develop --command ./gradlew testOssDebugUnitTest \
          --tests org.connectbot.portal.PortalHubRepositoryTest \
          --tests org.connectbot.portal.PortalHubContractTest
    )
  else
    echo "Java is not on PATH and nix develop is unavailable for ${android_root}" >&2
    exit 1
  fi
else
  echo "Skipping Portal Android; not found at ${android_root}" >&2
fi
