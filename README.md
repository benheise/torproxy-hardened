# torproxy-hardened

A Tor SOCKS5 proxy container built on [Arti](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Rust implementation of Tor, running as a single process on Chainguard's `glibc-dynamic` base. It replaces `avpnusr/torprivoxy:latest-debian` for clients that use SOCKS5 only.

The image has no shell and no package manager, and runs as UID 65532. It works with a read-only root filesystem, all capabilities dropped, and `no-new-privileges`.

## Why this replaces the Debian image

| | avpnusr/torprivoxy:latest-debian | torproxy:arti |
|---|---|---|
| Tor implementation | C tor 0.4.9.11 (Debian) | Arti 2.8.0 (Rust, memory-safe) |
| HTTP proxy | Privoxy 4.0.0 on 8118 | none (SOCKS5 only) |
| Bridges / PTs | obfs4proxy 0.0.14 (unmaintained) | lyrebird 0.10.0 (obfs4, webtunnel, meek_lite, snowflake) |
| Base | Debian 13, 131 deb packages | Chainguard glibc-dynamic, 7 apk packages |
| Process model | tini + runit + shell entrypoint | Arti is PID 1 |
| Trivy (2026-11-20) | 292 CVEs (13 critical, 155 high) | 0 |
| Grype (2026-11-20) | 293 CVEs (51 critical, 248 high) | 2 (glibc, medium + low, no upstream fix) |
| Compressed / unpacked size | 62.2 MB / 263 MB | 23.4 MB / 81.2 MB |
| Works as published | No (see below) | Yes |

The published `latest-debian` image does not currently work. The `tordocker` user's home directory is `/nonexistent` and the torrc sets no `DataDirectory`, so tor fails config validation and runit restarts it every second. Its `BRIDGE` handling is also broken: `torrc.base` has no trailing newline, which merges lines into `BridgeRelay 0UseBridges 1`, and a `printf '%sn'` typo drops every bridge after the first.

Privoxy is gone. In the old image it loaded no action or filter files, so all it did was convert HTTP proxy requests to SOCKS. Clients that need an HTTP proxy are not supported by this image.

## Run

CI publishes signed images to `ghcr.io/<owner>/<repo>` (see [CI](#ci)). Verify, then run:

```sh
scripts/verify-image.sh ghcr.io/<owner>/<repo>:latest
docker run -d --name torproxy --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 \
  -v arti-data:/var/lib/arti -p 127.0.0.1:9050:9050 ghcr.io/<owner>/<repo>:latest
```

To build and run locally instead: `docker compose up -d` (uses `compose.yaml`). For a Portainer stack, paste `deploy/portainer-stack.yml` into the web editor and replace the digest.

Point clients at `socks5h://127.0.0.1:9050`. Use the `socks5h` form (hostname sent to the proxy) so DNS resolution happens inside Tor. This image has no DNS port. A client that resolves names itself and hands the proxy an IP address leaks those lookups outside Tor.

Publish 9050 only to loopback or a private network. Arti logs a warning that it listens on a non-local address. That is expected inside a container, but anything that can reach the published port can use your Tor client.

The `/var/lib/arti` volume holds guard state and the directory cache. Keep it across restarts. A named volume gets the right ownership automatically. A bind mount must be owned by 65532:65532 with mode 0700.

### Bridges

Mount a TOML file into `/etc/arti/arti.d/`:

```toml
[bridges]
enabled = true
bridges = [
  "obfs4 192.0.2.10:443 FINGERPRINT cert=... iat-mode=0",
]

[[bridges.transports]]
protocols = ["obfs4", "webtunnel"]
path = "/usr/bin/lyrebird"
run_on_startup = false
```

```sh
sudo chown root:root bridges.toml && sudo chmod 0644 bridges.toml
-v ./bridges.toml:/etc/arti/arti.d/bridges.toml:ro
```

The file must be owned by root (or by UID 65532) and not writable by group or others. Arti refuses any other config file and exits with `Bad owner (UID …) on file or directory`, so a file you created as your normal user needs the `chown` above. Arti starts lyrebird when a bridge needs it and stops it on shutdown.

### Healthcheck

`/usr/bin/healthcheck` fetches `https://check.torproject.org/api/ip` through the local SOCKS5 port and requires `IsTor: true`. Override it with `HEALTHCHECK_URL` (any 2xx/3xx counts as healthy; `.onion` HTTPS skips certificate checks because the onion address authenticates the service) and `HEALTHCHECK_PROXY`.

### Stopping

The image sets `STOPSIGNAL SIGINT`. As PID 1, Arti ignores SIGTERM, so without this `docker stop` waits the full timeout and kills it (exit 137). With SIGINT it shuts down in under a second with exit 0.

## Migrating from the Debian image

- Port 8118 (Privoxy) is gone. Use SOCKS5 on 9050.
- The data path is `/var/lib/arti` and the UID is 65532 (the old image used `tordocker`, UID 102).
- The `BRIDGE` environment variable is replaced by a mounted `bridges.toml`.
- There is no shell, so `docker exec ... sh` doesn't work. Debug with `docker logs`, or run a throwaway container with an overridden entrypoint such as `--entrypoint /usr/bin/arti torproxy:arti --version`.

## Build

```sh
docker buildx build -t torproxy:arti .
```

Behind a TLS-inspecting proxy, pass its CA as a BuildKit secret; it is used only in build stages and never reaches the final image:

```sh
docker buildx build --secret id=ca,src=/path/to/corp-ca.pem -t torproxy:arti .
```

The first build compiles Arti (about 9 minutes on 2 cores). Cargo's registry and target directories are BuildKit cache mounts, so later rebuilds and version bumps are incremental. Chainguard's free images publish amd64 and arm64. For arm64, build on an arm64 runner; compiling Arti under QEMU is very slow.

### Supply chain

- **Arti**: built from crates.io with `--locked`, so the release's `Cargo.lock` pins the whole dependency tree and cargo verifies crate checksums. It uses `rustls-ring` instead of OpenSSL. HTTP CONNECT and the DNS proxy are not compiled in. `cargo auditable` embeds all 412 crates in the binary, so syft, trivy and grype can inventory and scan them.
- **lyrebird**: fetched through the Go module proxy and verified against sum.golang.org. Version 0.10.0 pins dependencies that govulncheck reports as reachable (`golang.org/x/net`, `x/crypto`, `klauspost/compress`, `andybalholm/brotli`). The build bumps them with `LYREBIRD_DEP_BUMPS`, runs lyrebird's `go vet` and test suite, and then runs govulncheck.
- **Gate**: govulncheck runs on both Go binaries and fails the build on any reachable vulnerability. Override deliberately with `--build-arg GOVULNCHECK=0`.
- **Runtime libraries**: the build adds any shared libraries Arti needs to the base's apk database with `apk add --root`, so SBOM tools see them. Arti 2.8.0 needs only glibc and libgcc, which the base already provides, so no packages are added today.

### Keeping it current

```sh
scripts/bump-versions.sh           # current vs latest: Arti, lyrebird and every tool pin
scripts/bump-versions.sh --apply   # rewrite the Arti and lyrebird ARG pins, then rebuild and re-scan
```

When you bump lyrebird, check whether its `go.mod` already includes the `LYREBIRD_DEP_BUMPS` versions, and remove entries that are no longer needed. The govulncheck gate fails the build if a needed bump is missing.

The Chainguard base images use the free `:latest` tags, which are rebuilt continuously. Rebuild regularly (for example weekly in CI) to pick up base fixes, and pin by digest if you need reproducible builds.

## CI

`.github/workflows/build.yml` runs on pull requests, on pushes to `main`, every Monday at 05:23 UTC, and on demand. The weekly run rebuilds from scratch (no cache), so the image picks up fixes in the Chainguard base and build images even when nothing in the repository changed.

| Job | Pull request | `main` (push, schedule, manual) |
|---|---|---|
| Lint | hadolint, shellcheck, healthcheck `go vet`/tests, actionlint, zizmor (pedantic) | same |
| Build (amd64 and arm64, native runners) | build, smoke test, scan, gate; nothing pushed | fresh build pushed **by digest only**, then pulled back and smoke-tested, scanned and gated as pushed |
| Publish | — | index, sign, attest, verify, then move tags |

The smoke test (`ci/smoke-test.sh`) runs the image read-only with no capabilities, checks the user, stop signal, missing shell, version label, SOCKS5 handshake, clean stop, restart and the lyrebird launch for bridges. In CI (`REQUIRE_TOR=1`) it also waits for a real Tor bootstrap and requires `IsTor: true` both from the in-container healthcheck and from a host client over `socks5h`.

The vulnerability gate (`ci/gate.sh`) fails on any HIGH or CRITICAL finding from Trivy or Grype that has a fix. Unfixed findings are reported but don't fail. To accept a finding, add it to `ci/allowlist.txt` with an expiry date and a reason; expired entries stop applying.

Publishing happens only if every platform passed. `ci/publish.sh` then:

1. Creates the multi-platform index with only a `sha-<commit>` tag, and checks that it references exactly the digests that were tested and scanned.
2. Signs the index and each platform image with keyless cosign (the GitHub OIDC identity of this workflow on `main`).
3. Attests each platform's SPDX SBOM (Syft) and vulnerability report (Trivy, cosign-vuln format), and adds GitHub build provenance for the index.
4. Runs `scripts/verify-image.sh` against the digest. Only if every signature and attestation verifies does it move `latest`, `arti-<version>` and `<YYYY-MM-DD>`, and it then checks that each tag resolves to the signed digest.

Where the results go:

- **Images and attestations:** GHCR. Signatures, SBOMs and vulnerability reports are attached to each image as OCI referrers, or as `sha256-…` tags on registries without the referrers API.
- **Code scanning:** Trivy and Grype SARIF per platform, in the Security tab.
- **Workflow artifacts** (90 days): `scan-<arch>` holds all scan outputs, both SBOM formats (SPDX and CycloneDX) and the gate summary. `verified-attestations` holds the SBOMs and reports as extracted from the signed attestations.
- **Run summary:** per-platform scan counts, digests and tags, plus a drift report from `scripts/bump-versions.sh` for Arti, lyrebird and every pinned tool.

### Verifying an image

```sh
scripts/verify-image.sh ghcr.io/<owner>/<repo>:latest ./attestations
```

This checks the keyless signature on the index and each platform, the SBOM and vulnerability attestations, and the GitHub build provenance (needs `gh`, logged in). It accepts only signatures from `build.yml` on `refs/heads/main` of the repository in the image path, and rejects provenance from self-hosted runners. With a directory argument, it writes each platform's verified SBOM and vulnerability report there. It needs docker (buildx), cosign 3.x and jq.

### Setting up the repository

- Actions only needs the default read-only `GITHUB_TOKEN`; each job requests what it uses. The workflow sets `permissions: {}` and pins every action to a commit SHA, and Dependabot (`.github/dependabot.yml`) keeps those pins current with a 7-day cooldown.
- The first publish creates a private GHCR package. Make it public in the package settings if you want anonymous pulls. It links to the repository through the `org.opencontainers.image.source` label.
- `ubuntu-24.04-arm` runners are free on public repositories. On private repositories they have 2 vCPUs and use the plan's included Actions minutes.
- Code scanning needs a public repository or GitHub Advanced Security. Without it the SARIF upload is skipped, and the SARIF is still in the artifact.
- Require the `Lint`, `Build amd64` and `Build arm64` checks in branch protection for `main`.
- GitHub disables scheduled workflows after 60 days without repository activity. Re-enable the workflow from the Actions tab if that happens.
- On `main`, each build pushes platform images by digest before testing them. A run that fails the smoke test or gate leaves those untagged, unsigned digests in GHCR. Nothing references them; a GHCR retention policy or cleanup action can remove untagged versions.
- Harden-Runner runs in `audit` mode. After a few runs, its insights list the endpoints the jobs reach, and you can switch to `egress-policy: block` with those as `allowed-endpoints`.

### Running the CI steps locally

```sh
docker buildx build -t torproxy:arti .
ci/smoke-test.sh torproxy:arti               # add REQUIRE_TOR=1 if this host can reach Tor
ci/scan.sh torproxy:arti scan && ci/gate.sh scan
```

The scanners run as digest-pinned containers, so local results match CI.

## Caveats

- The Tor Project calls Arti fast-moving. Its CLI is not covered by semver, and it has no control port, so tools that speak Tor's control protocol (nyx, stem) won't work.
- Live Tor bootstrap was not verified where this image was first built, because outbound connections to Tor relays were blocked there. The CI smoke test covers it on every run (`REQUIRE_TOR=1`).
- The two remaining Grype findings are glibc issues with no upstream fix (CVE-2026-115819, medium: wide `scanf` family; CVE-2026-100290, low: `regcomp`/`regexec`). Arti's binary imports none of these functions (checked against its dynamic symbol table), and the Go binaries are static and don't use glibc.
