#!/usr/bin/env bash
# Scan an image with Trivy and Grype, and write SBOMs with Syft.
#
#   ci/scan.sh IMAGE OUTDIR
#
# IMAGE must be in the local Docker daemon (docker pull a registry image
# first). The scanners run as pinned container images, so local runs and CI
# use the same versions. Writes to OUTDIR:
#   trivy.json  trivy.sarif  trivy.cosign-vuln.json
#   grype.json  grype.sarif
#   sbom.spdx.json  sbom.cdx.json
#
# SCAN_CACHE (default ~/.cache/torproxy-scan) keeps the vulnerability DBs.
set -euo pipefail

TRIVY_IMAGE=${TRIVY_IMAGE:-ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb}
GRYPE_IMAGE=${GRYPE_IMAGE:-ghcr.io/anchore/grype:v0.122.1@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c}
SYFT_IMAGE=${SYFT_IMAGE:-ghcr.io/anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a}

image=${1:?usage: scan.sh IMAGE OUTDIR}
out=${2:?usage: scan.sh IMAGE OUTDIR}
docker image inspect "$image" >/dev/null 2>&1 || { echo "scan.sh: $image is not in the local Docker daemon" >&2; exit 2; }

mkdir -p "$out"
out=$(cd "$out" && pwd)
cache=${SCAN_CACHE:-$HOME/.cache/torproxy-scan}
mkdir -p "$cache/trivy" "$cache/grype"

sock=/var/run/docker.sock
args=(--rm --network host
  -u "$(id -u):$(id -g)" --group-add "$(stat -c %g "$sock")"
  -v "$sock:$sock:ro" -v "$out:/out" -e HOME=/tmp)
# Pass a proxy and CA bundle through when the host uses them (no-ops in CI).
for v in HTTPS_PROXY https_proxy NO_PROXY no_proxy; do
  [[ -n "${!v:-}" ]] && args+=(-e "$v")
done
if [[ -n "${SSL_CERT_FILE:-}" && -f "${SSL_CERT_FILE}" ]]; then
  args+=(-v "${SSL_CERT_FILE}:/etc/scan-ca.crt:ro" -e SSL_CERT_FILE=/etc/scan-ca.crt)
fi

echo "== trivy"
docker run "${args[@]}" -v "$cache/trivy:/cache" "$TRIVY_IMAGE" image \
  --quiet --cache-dir /cache --image-src docker --scanners vuln \
  --format json --output /out/trivy.json "$image"
for fmt in sarif cosign-vuln; do
  ext=$([[ $fmt == sarif ]] && echo sarif || echo cosign-vuln.json)
  docker run "${args[@]}" -v "$cache/trivy:/cache" "$TRIVY_IMAGE" convert \
    --quiet --format "$fmt" --output "/out/trivy.$ext" /out/trivy.json
done

echo "== grype"
docker run "${args[@]}" -v "$cache/grype:/cache" -e GRYPE_DB_CACHE_DIR=/cache "$GRYPE_IMAGE" \
  "docker:$image" --quiet -o json=/out/grype.json -o sarif=/out/grype.sarif

echo "== syft"
docker run "${args[@]}" "$SYFT_IMAGE" \
  "docker:$image" --quiet -o spdx-json=/out/sbom.spdx.json -o cyclonedx-json=/out/sbom.cdx.json

for f in trivy.json trivy.sarif trivy.cosign-vuln.json grype.json grype.sarif sbom.spdx.json sbom.cdx.json; do
  [[ -s "$out/$f" ]] || { echo "scan.sh: missing $out/$f" >&2; exit 1; }
done
printf 'scan.sh: wrote %s (SBOM components: %s)\n' "$out" "$(jq '.packages | length' "$out/sbom.spdx.json")"
