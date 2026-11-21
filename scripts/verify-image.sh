#!/usr/bin/env bash
# Verify a published torproxy image before deploying it.
#
#   scripts/verify-image.sh IMAGE[:TAG|@DIGEST] [OUTDIR]
#
# For the multi-platform index and each platform image, checks:
#   - a keyless cosign signature made by this repository's build workflow
#   - SPDX SBOM and vulnerability-report attestations from that workflow
#   - GitHub build provenance on the index (needs gh; skipped with a warning)
# With OUTDIR, the verified SBOM and vulnerability report for each platform
# are written there.
#
#   GITHUB_REPOSITORY  owner/repo that built the image (default: from IMAGE)
#   WORKFLOW_REF       ref the workflow ran on (default: refs/heads/main)
#   COSIGN_KEY         verify with a public key instead (testing only)
#   COSIGN_IGNORE_TLOG set to 1 to skip transparency-log checks (testing only)
#
# Needs: docker (buildx), cosign 3.x, jq.
set -euo pipefail

ref=${1:?usage: verify-image.sh IMAGE[:TAG|@DIGEST] [OUTDIR]}
outdir=${2:-}
for tool in docker cosign jq; do
  command -v "$tool" >/dev/null || { echo "verify-image.sh: $tool is required" >&2; exit 2; }
done

repo_path=${ref%@*}                          # strip @digest
[[ "${repo_path##*/}" == *:* ]] && repo_path=${repo_path%:*}   # strip :tag
gh_repo=${GITHUB_REPOSITORY:-$(cut -d/ -f2- <<<"$repo_path")}
workflow_ref=${WORKFLOW_REF:-refs/heads/main}
identity="https://github.com/${gh_repo}/.github/workflows/build.yml@${workflow_ref}"
issuer="https://token.actions.githubusercontent.com"

if [[ -n "${COSIGN_KEY:-}" ]]; then
  trust=(--key "$COSIGN_KEY")
  echo "trust: public key $COSIGN_KEY"
  if [[ "${COSIGN_IGNORE_TLOG:-}" == 1 ]]; then
    trust+=(--insecure-ignore-tlog=true)
    echo "trust: WARNING transparency log not checked (test mode)"
  fi
else
  trust=(--certificate-identity "$identity" --certificate-oidc-issuer "$issuer")
  echo "trust: $identity"
fi

raw=$(docker buildx imagetools inspect "$ref" --raw)
index=$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' | jq -r '.digest')
[[ "$index" == sha256:* ]] || { echo "verify-image.sh: could not resolve $ref" >&2; exit 1; }
echo "image: $repo_path@$index"

mapfile -t platforms < <(jq -r '.manifests[]?
  | select(.platform.os != "unknown" and .platform.architecture != "unknown")
  | "\(.platform.os)/\(.platform.architecture) \(.digest)"' <<<"$raw")
[[ ${#platforms[@]} -gt 0 ]] || { echo "verify-image.sh: $ref is not a multi-platform index" >&2; exit 1; }

failures=0
ok=0
check() { # description command... ; sets ok=1 on success, never aborts
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then
    ok=1; echo "  ok    $what"
  else
    ok=0; echo "  FAIL  $what"; failures=$((failures + 1))
  fi
}
predicate() { # type digest -> verified predicate JSON on stdout
  cosign verify-attestation "${trust[@]}" --type "$1" "$repo_path@$2" 2>/dev/null \
    | jq -s -c 'map(.payload | @base64d | fromjson) | last | .predicate'
}

echo "index"
check "cosign signature" cosign verify "${trust[@]}" "$repo_path@$index"
if [[ -n "${COSIGN_KEY:-}" ]]; then
  echo "  skip  build provenance (key mode)"
elif command -v gh >/dev/null; then
  check "GitHub build provenance" gh attestation verify "oci://$repo_path@$index" \
    --repo "$gh_repo" --signer-workflow "${gh_repo}/.github/workflows/build.yml" --source-ref "$workflow_ref" \
    --deny-self-hosted-runners
else
  echo "  warn  build provenance not checked (install gh)"
fi

[[ -n "$outdir" ]] && mkdir -p "$outdir"
for entry in "${platforms[@]}"; do
  platform=${entry% *}; digest=${entry#* }
  echo "$platform $digest"
  arch=${platform#*/}
  check "cosign signature" cosign verify "${trust[@]}" "$repo_path@$digest"
  check "SBOM attestation (SPDX)" cosign verify-attestation "${trust[@]}" --type spdxjson "$repo_path@$digest"
  if (( ok )) && [[ -n "$outdir" ]]; then
    if predicate spdxjson "$digest" > "$outdir/sbom-$arch.spdx.json" && jq -e '.spdxVersion' "$outdir/sbom-$arch.spdx.json" >/dev/null; then
      echo "        wrote sbom-$arch.spdx.json ($(jq '.packages | length' "$outdir/sbom-$arch.spdx.json") packages)"
    else
      rm -f "$outdir/sbom-$arch.spdx.json"; echo "  FAIL  extract SBOM"; failures=$((failures + 1))
    fi
  fi
  check "vulnerability attestation" cosign verify-attestation "${trust[@]}" --type vuln "$repo_path@$digest"
  if (( ok )) && [[ -n "$outdir" ]]; then
    if predicate vuln "$digest" > "$outdir/vuln-$arch.json" && jq -e '.scanner' "$outdir/vuln-$arch.json" >/dev/null; then
      echo "        wrote vuln-$arch.json (scanned $(jq -r '.metadata.scanFinishedOn // "?"' "$outdir/vuln-$arch.json"))"
    else
      rm -f "$outdir/vuln-$arch.json"; echo "  FAIL  extract vulnerability report"; failures=$((failures + 1))
    fi
  fi
done

if (( failures )); then echo "verify-image.sh: $failures check(s) failed"; exit 1; fi
echo "verify-image.sh: all checks passed"
