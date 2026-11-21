#!/usr/bin/env bash
# Vulnerability gate over ci/scan.sh output.
#
#   ci/gate.sh OUTDIR [ALLOWLIST]
#
# Fails (exit 1) on any HIGH or CRITICAL finding from Trivy or Grype that has
# a fix available, unless the ID is in the allowlist (default
# ci/allowlist.txt next to this script) with an expiry date in the future.
# Unfixed findings are reported but do not fail the gate. Writes
# OUTDIR/summary.md for the CI job summary.
set -euo pipefail

out=${1:?usage: gate.sh OUTDIR [ALLOWLIST]}
allowlist=${2:-$(dirname "$0")/allowlist.txt}
today=$(date -u +%F)

for f in trivy.json grype.json; do
  [[ -s "$out/$f" ]] || { echo "gate.sh: missing $out/$f" >&2; exit 2; }
done

# Allowlist: "ID YYYY-MM-DD reason...". Expired or malformed lines don't apply.
declare -A allowed=()
expired=()
if [[ -f "$allowlist" ]]; then
  while read -r id expiry reason; do
    [[ -z "${id:-}" || "$id" == \#* ]] && continue
    if [[ ! "$expiry" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ || -z "${reason:-}" ]]; then
      echo "gate.sh: ignoring malformed allowlist line for $id (need: ID YYYY-MM-DD reason)" >&2
      continue
    fi
    if [[ "$expiry" < "$today" ]]; then expired+=("$id (expired $expiry)"); continue; fi
    allowed[$id]="$expiry $reason"
  done < "$allowlist"
fi

# One line per fixable HIGH/CRITICAL finding: tool|id|aliases|severity|package|installed|fixed
fixable=$(
  jq -r '.Results[]?.Vulnerabilities[]?
    | select(.Severity == "HIGH" or .Severity == "CRITICAL")
    | select((.FixedVersion // "") != "")
    | ["trivy", .VulnerabilityID, "", .Severity, .PkgName, .InstalledVersion, .FixedVersion] | join("|")' \
    "$out/trivy.json"
  jq -r '.matches[]
    | select(.vulnerability.severity == "High" or .vulnerability.severity == "Critical")
    | select(.vulnerability.fix.state == "fixed")
    | ["grype", .vulnerability.id, ([.relatedVulnerabilities[]?.id] | join(",")),
       (.vulnerability.severity | ascii_upcase), .artifact.name, .artifact.version,
       (.vulnerability.fix.versions | join(","))] | join("|")' \
    "$out/grype.json"
)

blocking=()
waived=()
while IFS='|' read -r tool id aliases sev pkg ver fix; do
  [[ -z "${tool:-}" ]] && continue
  hit=""
  for candidate in "$id" ${aliases//,/ }; do
    [[ -n "${allowed[$candidate]:-}" ]] && { hit=$candidate; break; }
  done
  row="| $tool | $id | $sev | $pkg | $ver | $fix |"
  if [[ -n "$hit" ]]; then waived+=("$row allowlisted as $hit until ${allowed[$hit]%% *} |"); else blocking+=("$row"); fi
done <<<"$fixable"

count() { # tool severity-list -> unique IDs per severity
  case $1 in
    trivy) jq -r '[.Results[]?.Vulnerabilities[]?] | unique_by(.VulnerabilityID) | group_by(.Severity)
             | map("\(.[0].Severity)=\(length)") | join(" ")' "$out/trivy.json" ;;
    grype) jq -r '[.matches[]] | unique_by(.vulnerability.id) | group_by(.vulnerability.severity)
             | map("\(.[0].vulnerability.severity | ascii_upcase)=\(length)") | join(" ")' "$out/grype.json" ;;
  esac
}

{
  echo "### Vulnerability gate: $([[ ${#blocking[@]} -eq 0 ]] && echo PASS || echo FAIL)"
  echo
  echo "| Scanner | Unique findings by severity |"
  echo "|---|---|"
  echo "| Trivy | $(count trivy | sed 's/^$/none/') |"
  echo "| Grype | $(count grype | sed 's/^$/none/') |"
  echo
  echo "Policy: fail on HIGH or CRITICAL with a fix available; unfixed findings are reported only."
  if [[ ${#blocking[@]} -gt 0 ]]; then
    echo; echo "**Blocking findings**"; echo
    echo "| Tool | ID | Severity | Package | Installed | Fixed in |"; echo "|---|---|---|---|---|---|"
    printf '%s\n' "${blocking[@]}" | sort -u
  fi
  if [[ ${#waived[@]} -gt 0 ]]; then
    echo; echo "**Allowlisted**"; echo
    echo "| Tool | ID | Severity | Package | Installed | Fixed in | Waiver |"; echo "|---|---|---|---|---|---|---|"
    printf '%s\n' "${waived[@]}" | sort -u
  fi
  if [[ ${#expired[@]} -gt 0 ]]; then
    echo; echo "Expired allowlist entries (no longer applied): ${expired[*]}"
  fi
} > "$out/summary.md"

cat "$out/summary.md"
[[ ${#blocking[@]} -eq 0 ]]
