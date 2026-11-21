#!/usr/bin/env bash
# Publish steps for the build workflow, kept here so they can be run against
# a test registry with the same code.
#
#   ci/publish.sh index            create the index from $SCANS/scan-*/digest,
#                                  tagged sha-<commit> only (a candidate)
#   ci/publish.sh sign DIGEST      sign the index and each platform image;
#                                  attest each platform's SBOM and vuln report
#   ci/publish.sh promote DIGEST   verify everything as a consumer would, then
#                                  tag latest, arti-<version>, <YYYY-MM-DD> and
#                                  check that every tag resolves to DIGEST
#
# Env: IMAGE (registry/name, no tag), SHA (commit), SOURCE (repository URL),
#      SCANS (default: scans), VERIFIED_DIR (default: verified),
#      GITHUB_OUTPUT (set by Actions; outputs are also printed).
# Test only: TEST_SIGNING_KEY and TEST_PUBLIC_KEY sign and verify with a key
# pair, without the transparency log, instead of keyless signing.
set -euo pipefail

cmd=${1:?usage: publish.sh index | sign DIGEST | promote DIGEST}
: "${IMAGE:?IMAGE is required}"
scans=${SCANS:-scans}
root=$(cd "$(dirname "$0")/.." && pwd)

out() { [[ -n "${GITHUB_OUTPUT:-}" ]] && echo "$1" >> "$GITHUB_OUTPUT"; echo "$1"; }
die() { echo "::error::$*" >&2; exit 1; }
digest_of() { docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r '.digest'; }
platform_digests() { # sorted list of the scanned platform digests
  local dir
  for dir in "$scans"/scan-*; do
    [[ -s "$dir/digest" ]] || die "$dir has no platform digest"
    cat "$dir/digest"
  done | sort
}

signing=()
if [[ -n "${TEST_SIGNING_KEY:-}" ]]; then
  signing=(--key "$TEST_SIGNING_KEY" --use-signing-config=false --tlog-upload=false)
  echo "publish.sh: TEST MODE, signing with $TEST_SIGNING_KEY and no transparency log" >&2
fi

case $cmd in
  index)
    : "${SHA:?SHA is required}" "${SOURCE:?SOURCE is required}"
    mapfile -t digests < <(platform_digests)
    [[ ${#digests[@]} -gt 0 ]] || die "no platform scans found in $scans"
    short=${SHA:0:12}
    docker buildx imagetools create \
      --annotation "index:org.opencontainers.image.source=$SOURCE" \
      --annotation "index:org.opencontainers.image.revision=$SHA" \
      --annotation "index:org.opencontainers.image.description=Arti Tor SOCKS5 proxy on Chainguard glibc-dynamic" \
      --tag "$IMAGE:sha-$short" "${digests[@]/#/$IMAGE@}"
    digest=$(digest_of "$IMAGE:sha-$short")
    [[ "$digest" == sha256:* ]] || die "could not read the index digest"
    # The index must reference exactly the images that were tested and scanned.
    listed=$(docker buildx imagetools inspect "$IMAGE@$digest" --raw | jq -r '.manifests[].digest' | sort)
    [[ "$listed" == "$(printf '%s\n' "${digests[@]}")" ]] || die "index manifests differ from the scanned digests"
    out "digest=$digest"
    out "short=$short"
    ;;

  sign)
    digest=${2:?usage: publish.sh sign DIGEST}
    cosign sign --yes "${signing[@]}" --recursive "$IMAGE@$digest"
    for dir in "$scans"/scan-*; do
      platform=$(cat "$dir/digest")
      cosign attest --yes "${signing[@]}" --type spdxjson --predicate "$dir/sbom.spdx.json" "$IMAGE@$platform"
      cosign attest --yes "${signing[@]}" --type vuln --predicate "$dir/trivy.cosign-vuln.json" "$IMAGE@$platform"
    done
    ;;

  promote)
    digest=${2:?usage: publish.sh promote DIGEST}
    : "${SHA:?SHA is required}"
    COSIGN_KEY=${TEST_PUBLIC_KEY:-} COSIGN_IGNORE_TLOG=${TEST_PUBLIC_KEY:+1} \
      "$root/scripts/verify-image.sh" "$IMAGE@$digest" "${VERIFIED_DIR:-verified}"
    arti=$(sed -n 's/^ARG ARTI_VERSION=//p' "$root/Dockerfile")
    [[ -n "$arti" ]] || die "ARTI_VERSION not found in the Dockerfile"
    tags=(latest "arti-$arti" "$(date -u +%F)")
    args=()
    for t in "${tags[@]}"; do args+=(--tag "$IMAGE:$t"); done
    docker buildx imagetools create "${args[@]}" "$IMAGE@$digest"
    for t in "${tags[@]}" "sha-${SHA:0:12}"; do
      got=$(digest_of "$IMAGE:$t")
      [[ "$got" == "$digest" ]] || die "$IMAGE:$t resolves to $got, not the signed digest $digest"
      echo "publish.sh: $IMAGE:$t -> $digest"
    done
    out "tags=${tags[*]} sha-${SHA:0:12}"
    ;;

  *) die "unknown command $cmd" ;;
esac
