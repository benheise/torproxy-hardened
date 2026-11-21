#!/usr/bin/env bash
# Report (and optionally apply) the latest Arti and lyrebird versions, and
# report drift in the build and CI tool pins.
#
#   scripts/bump-versions.sh           show current vs latest
#   scripts/bump-versions.sh --apply   rewrite the Arti and lyrebird ARG pins
#                                      in ./Dockerfile (tool pins are report-only)
#
# Arti comes from crates.io and is built with --locked, so its whole
# dependency tree is pinned by the release's Cargo.lock. Lyrebird tags are not
# semver, so the pin is the Go pseudo-version of the tag's commit, which the
# Go toolchain verifies against sum.golang.org at build time.
set -euo pipefail

cd "$(dirname "$0")/.."
dockerfile=Dockerfile
lyre_project='tpo%2Fanti-censorship%2Fpluggable-transports%2Flyrebird'
lyre_module='gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird'

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need curl
need jq
need git

current() { sed -n "s/^ARG $1=//p" "$dockerfile"; }

# Arti: newest non-yanked release on crates.io.
arti_latest=$(curl -fsS https://index.crates.io/ar/ti/arti \
  | jq -rs '[.[] | select(.yanked | not)] | last | .vers')
arti_msrv=$(curl -fsS https://index.crates.io/ar/ti/arti \
  | jq -rs --arg v "$arti_latest" '.[] | select(.vers == $v) | .rust_version // "unknown"')

# Lyrebird: newest tag, its commit, and the matching Go pseudo-version.
tag_json=$(curl -fsS "https://gitlab.torproject.org/api/v4/projects/${lyre_project}/repository/tags?per_page=1")
lyre_tag=$(jq -r '.[0].name' <<<"$tag_json")
lyre_commit=$(jq -r '.[0].commit.id' <<<"$tag_json")
lyre_latest=${lyre_tag#lyrebird-}
lyre_pseudo=$(curl -fsS "https://proxy.golang.org/${lyre_module}/@v/${lyre_commit:0:12}.info" | jq -r .Version)

printf '%-26s %-40s %s\n' ARG current latest
printf '%-26s %-40s %s (MSRV %s)\n' ARTI_VERSION "$(current ARTI_VERSION)" "$arti_latest" "$arti_msrv"
printf '%-26s %-40s %s\n' LYREBIRD_VERSION "$(current LYREBIRD_VERSION)" "$lyre_latest"
printf '%-26s %-40s %s\n' LYREBIRD_MODULE_VERSION "$(current LYREBIRD_MODULE_VERSION)" "$lyre_pseudo"
echo "lyrebird tag ${lyre_tag} -> commit ${lyre_commit}"

# Tool pins (report only): scanners and linters in ci/scan.sh and the
# workflow, build helpers in the Dockerfile. Image digests change with the tag,
# so a bump means updating both the tag and the @sha256 digest.
gh_latest() { # owner/repo -> newest vX.Y.Z tag without the v
  git ls-remote --tags "https://github.com/$1" 2>/dev/null \
    | sed -n 's#.*refs/tags/v\([0-9]*\.[0-9]*\.[0-9]*\)$#\1#p' | sort -V | tail -1
}
pin() { sed -n "$2" "$1" | head -1; }
workflow=.github/workflows/build.yml
tools=(
  "trivy|$(pin ci/scan.sh 's/.*trivy:\([0-9.]*\)@.*/\1/p')|$(gh_latest aquasecurity/trivy)"
  "grype|$(pin ci/scan.sh 's/.*grype:v\([0-9.]*\)@.*/\1/p')|$(gh_latest anchore/grype)"
  "syft|$(pin ci/scan.sh 's/.*syft:v\([0-9.]*\)@.*/\1/p')|$(gh_latest anchore/syft)"
  "hadolint|$(pin "$workflow" 's/.*hadolint:v\([0-9.]*\)@.*/\1/p')|$(gh_latest hadolint/hadolint)"
  "actionlint|$(pin "$workflow" 's/.*ACTIONLINT_VERSION: v\([0-9.]*\).*/\1/p')|$(gh_latest rhysd/actionlint)"
  "cosign|$(pin "$workflow" 's/.*cosign-release: v\([0-9.]*\).*/\1/p')|$(gh_latest sigstore/cosign)"
  "zizmor|$(pin "$workflow" 's/.*ZIZMOR_VERSION: \([0-9.]*\).*/\1/p')|$(curl -fsS https://pypi.org/pypi/zizmor/json | jq -r .info.version)"
  "govulncheck|$(current GOVULNCHECK_VERSION | tr -d v)|$(curl -fsS https://proxy.golang.org/golang.org/x/vuln/@latest | jq -r .Version | tr -d v)"
  "cargo-auditable|$(current CARGO_AUDITABLE_VERSION)|$(curl -fsS https://index.crates.io/ca/rg/cargo-auditable | jq -rs '[.[] | select(.yanked | not)] | last | .vers')"
)
echo
printf '%-26s %-40s %s\n' tool pinned latest
for t in "${tools[@]}"; do
  IFS='|' read -r name have want <<<"$t"
  mark=""; [[ -n "$want" && "$have" != "$want" ]] && mark="  <- update available"
  printf '%-26s %-40s %s%s\n' "$name" "${have:-?}" "${want:-?}" "$mark"
done

if [[ "${1:-}" == "--apply" ]]; then
  sed -i \
    -e "s/^ARG ARTI_VERSION=.*/ARG ARTI_VERSION=${arti_latest}/" \
    -e "s/^ARG LYREBIRD_VERSION=.*/ARG LYREBIRD_VERSION=${lyre_latest}/" \
    -e "s/^ARG LYREBIRD_MODULE_VERSION=.*/ARG LYREBIRD_MODULE_VERSION=${lyre_pseudo}/" \
    -e "s/^# lyrebird .*: tag .* = commit .*/# lyrebird (maintained successor of obfs4proxy): tag ${lyre_latest} = commit ${lyre_commit:0:8},/" \
    "$dockerfile"
  echo "updated ${dockerfile}; rebuild, re-test and re-scan before publishing"
fi
