# syntax=docker/dockerfile:1.7
#
# LayerSecOps - minimal image for CI/CD security gates.
#
# Build (offline DB not baked by default):
#   docker build -t layersecops:latest -f docker/Dockerfile .
#
# Build with a pre-baked vulnerability database (faster, air-gapped runs):
#   docker build --build-arg BAKE_DB=true -t layersecops:latest -f docker/Dockerfile .
#
# Pin tool versions:
#   docker build --build-arg TRIVY_VERSION=0.76.2 --build-arg GRYPE_VERSION=0.122.1 ...
#
# Run:
#   docker run --rm \
#     -v "$PWD:/work" -v "$PWD/reports:/reports" \
#     layersecops:latest scan --image-tar /work/app.tar \
#       --format json,sarif,html,metrics --output-dir /reports
#
# Exit codes: 0 pass, 1 policy failure, 2 scan/tool failure, 3 bad usage.

ARG PYTHON_VERSION=3.13
ARG TRIVY_VERSION=0.76.2
ARG GRYPE_VERSION=0.122.1
ARG SYFT_VERSION=1.57.2
ARG DIVE_VERSION=0.13.1

# ---------------------------------------------------------------------------
# Stage 1: download the four static Go binaries.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS tools

ARG TARGETARCH
ARG TRIVY_VERSION
ARG GRYPE_VERSION
ARG SYFT_VERSION
ARG DIVE_VERSION

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Normalise the buildx architecture name to the one used by the projects.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) GOARCH=amd64; TRIVY_ARCH=64bit ;; \
        arm64) GOARCH=arm64; TRIVY_ARCH=ARM64 ;; \
        *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 2 ;; \
    esac; \
    mkdir -p /opt/layersecops/bin; \
    \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
      | tar -xz -C /opt/layersecops/bin trivy; \
    \
    curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${GOARCH}.tar.gz" \
      | tar -xz -C /opt/layersecops/bin grype; \
    \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${GOARCH}.tar.gz" \
      | tar -xz -C /opt/layersecops/bin syft; \
    \
    curl -fsSL "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_${GOARCH}.tar.gz" \
      | tar -xz -C /opt/layersecops/bin dive; \
    \
    chmod 0755 /opt/layersecops/bin/*; \
    /opt/layersecops/bin/trivy --version; \
    /opt/layersecops/bin/grype --version; \
    /opt/layersecops/bin/syft --version; \
    /opt/layersecops/bin/dive --version

# ---------------------------------------------------------------------------
# Stage 2: install LayerSecOps itself.
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ARG PYTHON_VERSION
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LAYERSECOPS_CACHE_DIR=/var/cache/layersecops \
    GRYPE_DB_CACHE_DIR=/var/cache/layersecops/grype \
    TRIVY_CACHE_DIR=/var/cache/layersecops/trivy \
    PATH=/opt/layersecops/bin:/usr/local/bin:/usr/bin:/bin

# ca-certificates is needed for DB downloads; bash is used by helper scripts.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tools /opt/layersecops/bin /opt/layersecops/bin

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
 && rm -rf /app/src /app/README.md /app/pyproject.toml

# ---------------------------------------------------------------------------
# Optional vulnerability-database bake (air-gapped / fast CI runs).
# ---------------------------------------------------------------------------
FROM runtime AS dbseed
ARG BAKE_DB=false
USER root
RUN mkdir -p /var/cache/layersecops/trivy /var/cache/layersecops/grype \
 && if [ "${BAKE_DB}" = "true" ]; then \
      trivy image --download-db-only --cache-dir /var/cache/layersecops/trivy; \
      grype db update; \
    fi \
 && chown -R 10001:10001 /var/cache/layersecops

# ---------------------------------------------------------------------------
# Final image: non-root, minimal, CI-friendly.
# ---------------------------------------------------------------------------
FROM runtime AS final

LABEL org.opencontainers.image.title="LayerSecOps" \
      org.opencontainers.image.description="Scan Docker image archives for CVEs and layer-level findings" \
      org.opencontainers.image.source="https://github.com/layersecops/layersecops" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="0.1.0"

COPY --from=dbseed /var/cache/layersecops /var/cache/layersecops

RUN mkdir -p /work /reports \
 && chown -R 10001:10001 /work /reports /var/cache/layersecops

USER 10001:10001
WORKDIR /work

# Observability: every run prints a structured JSON line per log message when
# LAYERSECOPS_LOG_FORMAT=json, and writes report.prom (Prometheus text) when
# --format includes 'metrics'.
ENV LAYERSECOPS_LOG_FORMAT=text

ENTRYPOINT ["layersecops"]
CMD ["--help"]
