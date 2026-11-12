# Ananke worker image: the sandbox every run's commands, scanners and tests execute in.
# Build with BuildKit:  docker build -f docker/worker.Dockerfile -t ghcr.io/renci/ananke-worker:latest .
# Tool versions are explicit build args so upgrades are reviewable. They match the schemas the
# parse fixtures in tests/fixtures/scanner_output/ follow (see its README).
# No credentials are ever baked in or passed to this image.
FROM python:3.12-slim

ARG TARGETARCH
ARG UV_VERSION=0.13.7
ARG NODE_VERSION=22.14.0
ARG GO_VERSION=1.23.6
ARG TRIVY_VERSION=0.76.2
ARG OSV_SCANNER_VERSION=2.7.1
ARG GITLEAKS_VERSION=8.30.1

# Containers run as the *host* user's uid (DockerSandbox --user) so files written to the
# bind-mounted workspace stay host-owned. HOME and tool caches are on the per-run /tmp tmpfs
# (set by DockerSandbox); the scanner databases below are world-readable/writable for that uid.
ENV PATH=/usr/local/bin:/usr/local/go/bin:$PATH \
    TRIVY_CACHE_DIR=/opt/ananke/cache/trivy \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/ananke/cache/osv-scanner \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git tar xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) node_arch=x64; go_arch=amd64; trivy_arch=64bit; osv_arch=amd64; gitleaks_arch=x64 ;; \
      arm64) node_arch=arm64; go_arch=arm64; trivy_arch=ARM64; osv_arch=arm64; gitleaks_arch=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" -o /tmp/node.tar.xz; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1; \
    rm /tmp/node.tar.xz; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" -o /tmp/go.tar.gz; \
    tar -xzf /tmp/go.tar.gz -C /usr/local; \
    rm /tmp/go.tar.gz; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" -o /tmp/trivy.tar.gz; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz; \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}" -o /usr/local/bin/osv-scanner; \
    chmod 0755 /usr/local/bin/osv-scanner; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" -o /tmp/gitleaks.tar.gz; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tar.gz; \
    python -m pip install --no-cache-dir "uv==${UV_VERSION}"; \
    node --version; npm --version; go version; trivy --version; osv-scanner --version; gitleaks version

# Bake the vulnerability databases so runs are reproducible and need no DB egress:
#  - Trivy: runs use --skip-db-update.
#  - OSV-Scanner: runs use --offline; seed the PyPI, npm and Go databases from tiny manifests.
RUN set -eux; \
    mkdir -p "${TRIVY_CACHE_DIR}" "${OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY}" /tmp/osv-seed/py /tmp/osv-seed/js /tmp/osv-seed/go; \
    trivy image --download-db-only; \
    printf 'requests==2.25.1\n' > /tmp/osv-seed/py/requirements.txt; \
    printf '{"name":"seed","lockfileVersion":3,"packages":{"":{"name":"seed"},"node_modules/lodash":{"version":"4.17.15"}}}\n' > /tmp/osv-seed/js/package-lock.json; \
    printf 'module seed\n\ngo 1.21\n\nrequire golang.org/x/net v0.10.0\n' > /tmp/osv-seed/go/go.mod; \
    osv-scanner scan --offline-vulnerabilities --download-offline-databases -r /tmp/osv-seed >/dev/null || [ "$?" -eq 1 ]; \
    rm -rf /tmp/osv-seed; \
    chmod -R a+rwX /opt/ananke/cache

RUN useradd --create-home --uid 1000 --shell /bin/bash ananke && install -d -m 1777 /workspace
USER ananke
WORKDIR /workspace

CMD ["sleep", "infinity"]
