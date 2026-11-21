# syntax=docker/dockerfile:1.7
#
# Tor SOCKS5 proxy: Arti (the Tor Project's Rust Tor implementation) as a
# single process on Chainguard glibc-dynamic. No shell, no package manager,
# non-root. Replaces avpnusr/torprivoxy:latest-debian for SOCKS5-only use.
#
# Build:  docker buildx build -t torproxy:arti .
# Behind a TLS-inspecting proxy, add:  --secret id=ca,src=/path/to/corp-ca.pem
# Version bumps:  scripts/bump-versions.sh [--apply]

ARG RUST_IMAGE=cgr.dev/chainguard/rust:latest
ARG GO_IMAGE=cgr.dev/chainguard/go:latest
ARG WOLFI_BASE=cgr.dev/chainguard/wolfi-base:latest
ARG RUNTIME_BASE=cgr.dev/chainguard/glibc-dynamic:latest

# Arti from crates.io, built with --locked (dependency tree pinned by the
# release's Cargo.lock; crate checksums verified by cargo).
ARG ARTI_VERSION=2.8.0
ARG CARGO_AUDITABLE_VERSION=0.7.7
# lyrebird (maintained successor of obfs4proxy): tag 0.10.0 = commit 59ac7e40,
# fetched through the Go module proxy and verified against sum.golang.org.
ARG LYREBIRD_VERSION=0.10.0
ARG LYREBIRD_MODULE_VERSION=v0.0.0-20261104192811-59ac7e400c38
# Lyrebird 0.10.0 pins dependencies with advisories that govulncheck reports
# as reachable: GO-2026-6603/6610/6611/6612/6617 (x/net), GO-2026-5932
# (x/crypto), GO-2026-6865 (klauspost/compress), GO-2026-6888 (brotli).
# Bump them at build time; drop entries once upstream lyrebird includes them.
ARG LYREBIRD_DEP_BUMPS="golang.org/x/net@v0.63.0 golang.org/x/crypto@v0.59.0 github.com/klauspost/compress@v1.20.5 github.com/andybalholm/brotli@v1.3.0"
# Fail the build if govulncheck finds reachable vulnerabilities in the Go
# binaries. Override only deliberately: --build-arg GOVULNCHECK=0
ARG GOVULNCHECK=1
ARG GOVULNCHECK_VERSION=v1.10.0

# ------------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS arti
ARG ARTI_VERSION CARGO_AUDITABLE_VERSION
# Builder stage only; the final image runs as 65532.
# hadolint ignore=DL3002
USER 0
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
ENV CARGO_HOME=/cargo CARGO_HTTP_CAINFO=/etc/ssl/certs/ca-certificates.crt
# Features: SOCKS5 client with bridges, pluggable transports, onion-service
# client and vanguards. rustls-ring instead of native-tls (no OpenSSL);
# HTTP CONNECT and the DNS proxy are not compiled in.
# cargo-auditable embeds the crate list in the binary so syft, trivy and
# grype can inventory and scan Arti's dependencies.
RUN --mount=type=secret,id=ca,required=false \
    --mount=type=cache,target=/cargo/registry \
    --mount=type=cache,target=/target \
    if [ -s /run/secrets/ca ]; then cat /run/secrets/ca >> /etc/ssl/certs/ca-certificates.crt; fi \
 && cargo install --locked --root /tools cargo-auditable --version "${CARGO_AUDITABLE_VERSION}" \
 && PATH="/tools/bin:$PATH" cargo auditable install --locked --root /out --target-dir /target \
      arti --version "${ARTI_VERSION}" --no-default-features \
      --features tokio,rustls-ring,static-sqlite,compression,harden,bridge-client,pt-client,onion-service-client,vanguards \
 && strip --strip-unneeded /out/bin/arti \
 && readelf -d /out/bin/arti | sed -n 's/.*(NEEDED).*\[\(.*\)\]/so:\1/p' | sort -u > /out/.needed-so \
 && cat /out/.needed-so

# ------------------------------------------------------------------------------
FROM ${GO_IMAGE} AS gobuild
ARG ARTI_VERSION LYREBIRD_VERSION LYREBIRD_MODULE_VERSION LYREBIRD_DEP_BUMPS GOVULNCHECK GOVULNCHECK_VERSION
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
# LYREBIRD_DEP_BUMPS is split into words on purpose; govulncheck is pinned
# through GOVULNCHECK_VERSION.
# hadolint ignore=SC2086,DL3003,DL3062
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then cat /run/secrets/ca >> /etc/ssl/certs/ca-certificates.crt; fi \
 && GOBIN=/tools go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" \
 && src="$(go mod download -json "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird@${LYREBIRD_MODULE_VERSION}" \
      | sed -n 's/.*"Dir": "\(.*\)".*/\1/p')" \
 && mkdir -p /src && cp -r "$src" /src/lyrebird && chmod -R u+w /src/lyrebird && cd /src/lyrebird \
 && go get ${LYREBIRD_DEP_BUMPS} && go mod tidy \
 && go vet ./... && go test ./... \
 && go build -ldflags="-s -w -buildid= -X main.lyrebirdVersion=${LYREBIRD_VERSION}" -o /out/lyrebird ./cmd/lyrebird \
 && if [ "${GOVULNCHECK}" = 1 ]; then /tools/govulncheck ./...; else echo "WARNING: govulncheck gate disabled"; fi
COPY healthcheck/ /src/healthcheck/
WORKDIR /src/healthcheck
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then cat /run/secrets/ca >> /etc/ssl/certs/ca-certificates.crt; fi \
 && go vet ./... && go test ./... \
 && go build -ldflags="-s -w -buildid= -X main.version=arti-${ARTI_VERSION}_lyrebird-${LYREBIRD_VERSION}" -o /out/healthcheck . \
 && if [ "${GOVULNCHECK}" = 1 ]; then /tools/govulncheck ./...; fi

# ------------------------------------------------------------------------------
# Add any runtime libraries Arti needs to a copy of the base filesystem with
# apk --root, then keep only what changed, so the final image is the base's
# layers plus one delta layer and the apk database stays accurate.
FROM ${RUNTIME_BASE} AS runtime-base
FROM ${WOLFI_BASE} AS rootfs
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
COPY --from=runtime-base / /rootfs/
COPY --from=arti /out/.needed-so /tmp/needed-so
# The so: list is split into words on purpose; so: names cannot be version-pinned.
# hadolint ignore=SC2046,DL3003,DL3018
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then cat /run/secrets/ca >> /etc/ssl/certs/ca-certificates.crt; fi \
 && set -eu \
 && (cd /rootfs && find . -mindepth 1 | sort) > /tmp/before \
 && apk add --root /rootfs --no-cache --no-scripts \
      --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories \
      $(cat /tmp/needed-so) \
 && (cd /rootfs && find . -mindepth 1 | sort) > /tmp/after \
 && mkdir /delta \
 && comm -13 /tmp/before /tmp/after > /tmp/new \
 && echo ./usr/lib/apk/db/installed >> /tmp/new \
 && echo ./etc/apk/world >> /tmp/new \
 && while IFS= read -r p; do \
      if [ -d "/rootfs/$p" ] && [ ! -L "/rootfs/$p" ]; then mkdir -p "/delta/$p"; \
      else mkdir -p "/delta/$(dirname "$p")" && cp -a "/rootfs/$p" "/delta/$p"; fi; \
    done < /tmp/new \
 && install -d -m 0755 /delta/etc/arti/arti.d \
 && install -d -o 65532 -g 65532 -m 0700 /delta/var/lib/arti \
 && grep -E '^(P|V):' /rootfs/usr/lib/apk/db/installed | paste - -

# ------------------------------------------------------------------------------
FROM ${RUNTIME_BASE}
ARG ARTI_VERSION LYREBIRD_VERSION
COPY --link --from=rootfs  /delta/ /
COPY --link --from=arti    /out/bin/arti /usr/bin/arti
COPY --link --from=gobuild /out/lyrebird /out/healthcheck /usr/bin/
COPY --link arti.toml /etc/arti/arti.toml

LABEL org.opencontainers.image.title="torproxy-arti" \
      org.opencontainers.image.description="Arti (Rust Tor client) SOCKS5 proxy on Chainguard glibc-dynamic (non-root, no shell)" \
      org.opencontainers.image.base.name="cgr.dev/chainguard/glibc-dynamic:latest" \
      dev.torproxy.arti.version="${ARTI_VERSION}" \
      dev.torproxy.lyrebird.version="${LYREBIRD_VERSION}"

USER 65532:65532
EXPOSE 9050/tcp
# Arti shuts down cleanly on SIGINT; as PID 1 it does not act on SIGTERM.
STOPSIGNAL SIGINT
VOLUME ["/var/lib/arti"]
HEALTHCHECK --interval=2m --timeout=30s --start-period=2m --start-interval=15s --retries=2 \
  CMD ["/usr/bin/healthcheck"]
ENTRYPOINT ["/usr/bin/arti", "proxy", "-c", "/etc/arti/arti.toml", "-c", "/etc/arti/arti.d/"]
