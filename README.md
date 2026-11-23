# LayerSecOps

Scan **Docker images** (not containers) for CVEs and secrets with
[Trivy](https://github.com/aquasecurity/trivy),
[Grype](https://github.com/anchore/grype),
[Syft](https://github.com/anchore/syft) and
[Dive](https://github.com/wagoodman/dive), then normalize every scanner into one
schema and attribute each finding to the Docker layer that owns the affected
package.

```
image reference ──docker save──▶ image.tar ──┬─▶ Trivy  ─┐
                                             ├─▶ Syft   ─┼─▶ normalize ─▶ dedupe ─▶ layer map ─▶ JSON / SARIF / HTML
                                             ├─▶ Grype  ─┤
                                             └─▶ Dive   ─┘
```

No container is started or mounted. The image is read from a tarball (or saved
from a local daemon), and all four tools inspect that archive. This keeps the
scan safe for untrusted images and suitable for CI.

## Why each tool

| Tool | Role |
| --- | --- |
| **Trivy** | OS and language package CVEs, optional secret detection, per-vulnerability layer hints |
| **Grype** | Independent CVE matching, CVSS/EPSS/KEV enrichment, package locations with layer IDs |
| **Syft** | SBOM/package inventory, package database file lists used for ownership mapping |
| **Dive** | Layer list, per-layer file trees, image efficiency/wasted-space metrics |

Findings are merged by vulnerability ID + package + installed version. Identifiers
are canonicalized (a GHSA whose advisory lists a CVE becomes the CVE, with the
GHSA kept in `aliases`). A CVE reported by both Trivy and Grype becomes one
finding with both sources recorded, the highest severity, the newest CVSS/EPSS
values and the union of fix versions.

## Layer attribution

The image is scanned once for each scope you choose, then every finding is
mapped back to a layer using this evidence order:

1. **exact** — a file owned by the package (from Syft metadata/locations) exists in a layer.
2. **tool** — Trivy or Grype reported a layer digest/diff-ID for the package.
3. **db** — the package-manager database file (dpkg status, apk installed DB, rpm DB) belongs to a layer.
4. **historical** — the file existed earlier but was deleted by a later layer.
5. **inferred** — a conservative filename/directory match (for example `libssl.so.3` for `libssl3`).
6. **unknown** — no evidence; the finding is still reported but not assigned a layer.

### Scanning per layer

By default Syft and Grype catalog the **final squashed filesystem**
(`--layer-scope squashed`), which is what validation of a built image should
check. Pass `--layer-scope all-layers` to also catalog files that a later layer
overwrote or deleted, so a package removed by `apk del` or `apt-get remove` is
still reported against the layer that introduced it:

```bash
layersecops scan --image-tar app.tar --layer-scope all-layers --format json,html
```

Every finding still carries the layer that owns the file (`confidence: exact`)
or, for deleted files, the layer that last contained it (`historical`), so a
per-layer report is available either way.

Dive supplies per-layer file trees; if Dive is unavailable or fails, LayerSecOps
streams the layer tarballs directly and reads member names without extracting
them. Whiteout files (`.wh.*`, opaque directories) are applied so a path is
owned by the last layer that actually provides it.

Each finding carries `layer.index`, `layer.digest`, `layer.diffId`,
`layer.command`, `layer.confidence`, `layer.evidence`, and `layer.path`.
Reports also include per-layer counts (`summary.byLayer`) and Dive efficiency
data.

Example: a three-layer image where layer 1 adds `curl` and layer 2 removes it.
With `--layer-scope all-layers` the curl CVEs are reported on layer 1; with the
default squashed scope they are absent because the final filesystem no longer
contains curl.

## Install

Requirements: Python 3.11+ (3.10 works with `tomli`), Bash or PowerShell for the
bootstrap scripts. Docker is only needed for `layersecops scan IMAGE`; scanning
`--image-tar` does not need a daemon.

```bash
# Linux / WSL / macOS
scripts/bootstrap-tools.sh
python -m pip install -e .

# Windows PowerShell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap-tools.ps1
python -m pip install -e .
```

The bootstrap scripts download the latest releases into `./.tools/bin` (or
`--dir`). Pin versions with `TRIVY_VERSION`, `GRYPE_VERSION`, `SYFT_VERSION`,
`DIVE_VERSION`. The CLI also looks in `LAYERSECOPS_TOOL_DIR`, `./.tools/bin`,
`./bin`, and `PATH`. If the `layersecops` command is not on `PATH` after
installation, use `python -m layersecops` instead.

Check what is installed:

```bash
layersecops tools
```

## Usage

```bash
# Local image: pull, save, scan
layersecops scan nginx:1.25 --pull --format json,sarif,html

# Scan an existing archive (no daemon, no container)
docker save nginx:1.25 -o nginx.tar
layersecops scan --image-tar nginx.tar

# Scan an OCI archive exported by skopeo
layersecops scan --image-tar nginx.oci.tar

# CI gate: fail on high/critical, ignore unfixed, write SARIF
layersecops scan registry.example.com/app:1.2.3 \
  --pull --format json,sarif \
  --fail-on high --ignore-unfixed \
  --output-dir reports/app-1.2.3

# Include Trivy secret scanning
layersecops scan --image-tar app.tar --scanners vuln,secret

# Re-apply a stricter policy without rescanning
layersecops validate reports/app-1.2.3/report.json --fail-on critical

# Keep raw scanner JSON and logs for debugging
layersecops scan --image-tar app.tar --keep-raw --sbom --keep-workdir
```

Default output is `reports/<image>-<timestamp>/` with `report.json` and
`report.html`. Add `sarif`, `table` (plain text) and/or `summary` to `--format`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and policy passed |
| `1` | Scan completed but policy failed |
| `2` | Scan error, missing required tool, or tool failure |
| `3` | Invalid configuration/usage |

### Options worth knowing

| Option | Description |
| --- | --- |
| `--tools trivy,grype,syft,dive` | Select which scanners run |
| `--require-tools trivy,grype,syft` | Tools that must succeed (default) |
| `--scanners vuln,secret` | Trivy scanners (default `vuln`) |
| `--layer-scope all-layers` | Also catalog files deleted or replaced by later layers |
| `--offline` | Skip Trivy DB update and Grype DB auto-update || `--min-severity high` | Only include findings at/above this severity in reports |
| `--ignore CVE-2023-*` | Ignore IDs/globs (repeatable) |
| `--ignore-package openssl` | Ignore package names/globs (repeatable) |
| `--max-critical 0 --max-high 2` | Count-based policy limits |
| `--platform linux/amd64` | Platform for `docker pull` |
| `--workdir DIR` | Keep working files in a known directory |

`--min-severity` filters what is written to the reports. The policy gate is
always evaluated against the full finding set, so a filtered report cannot hide
a failing severity. Selecting a subset with `--tools` also narrows the default
`require_tools` list unless you pass `--require-tools` explicitly.

## Unified schema (v1.0)

```json
{
  "schemaVersion": "1.0",
  "scan": {
    "id": "5b2d…",
    "status": "complete",
    "startedAt": "2026-01-01T12:00:00.000Z",
    "finishedAt": "2026-01-01T12:01:20.000Z",
    "image": {
      "reference": "nginx:1.25",
      "id": "sha256:…",
      "digest": "sha256:…",
      "architecture": "amd64",
      "os": "linux",
      "distro": {"name": "debian", "version": "12.5", "prettyName": "Debian GNU/Linux 12 (bookworm)"},
      "sizeBytes": 142000000,
      "layers": [
        {"index": 0, "digest": "sha256:…", "diffId": "sha256:…", "sizeBytes": 78000000, "command": "ADD rootfs.tar.xz /"}
      ],
      "efficiency": {"score": 0.92, "wastedBytes": 1200000, "wastedPercent": 8.1}
    },
    "options": {"tools": ["trivy", "grype", "syft", "dive"], "policy": {"failOn": "high"}},
    "tools": [{"name": "trivy", "status": "ok", "version": "0.58.0", "durationMs": 12000}],
    "warnings": [],
    "errors": []
  },
  "summary": {
    "total": 2,
    "bySeverity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "negligible": 0, "unknown": 0},
    "byLayer": [{"index": 0, "findings": 0, "critical": 0, "high": 0}],
    "fixable": 2,
    "knownExploited": 0
  },
  "validation": {"passed": false, "policy": {"failOn": "high"}, "violations": []},
  "findings": [
    {
      "id": "CVE-2024-1234:deb:libssl3@3.0.11-1",
      "kind": "vulnerability",
      "vulnerabilityId": "CVE-2024-1234",
      "aliases": ["GHSA-…"],
      "severity": "critical",
      "status": "fixed",
      "risk": {"score": 9.8, "source": "cvss"},
      "cvss": [{"version": "3.1", "score": 9.8, "vector": "CVSS:3.1/…", "source": "nvd"}],
      "epss": 0.42,
      "knownExploited": false,
      "package": {
        "name": "libssl3",
        "version": "3.0.11-1",
        "type": "deb",
        "ecosystem": "debian",
        "purl": "pkg:deb/debian/libssl3@3.0.11-1",
        "path": "usr/lib/x86_64-linux-gnu/libssl.so.3",
        "fixedVersions": ["3.0.13-1"]
      },
      "layer": {
        "index": 3,
        "digest": "sha256:…",
        "command": "RUN apt-get install -y libssl3",
        "confidence": "exact",
        "evidence": "package file is owned by layer 3",
        "path": "usr/lib/x86_64-linux-gnu/libssl.so.3"
      },
      "sources": [
        {"tool": "trivy", "scanner": "vuln", "vulnerabilityId": "CVE-2024-1234", "severity": "critical"},
        {"tool": "grype", "scanner": "vuln", "vulnerabilityId": "CVE-2024-1234", "severity": "critical"}
      ]
    }
  ]
}
```

Secrets are included as `kind: "secret"` findings with a rule ID, file path and
layer. The matched secret value is **never** copied into the report.

## Configuration

Create `layersecops.toml` next to where you run the CLI (or pass `--config`):

```toml
[scan]
tools = ["trivy", "grype", "syft", "dive"]
require_tools = ["trivy", "grype", "syft"]
scanners = ["vuln"]
# squashed (final filesystem) | all-layers (every layer) | deep-squashed
layer_scope = "squashed"
timeout_seconds = 900
offline = false
output_dir = "reports"
formats = ["json", "sarif", "html"]
sbom = true
keep_raw = false

[policy]
fail_on = "high"
ignore_unfixed = false
ignore = ["CVE-2023-12345", "GHSA-*"]
ignore_packages = []
max_critical = 0
max_high = 5
```

CLI flags override config values. `--ignore-file` accepts one ID/glob per line
with `#` comments.

## CI example

```yaml
- name: Scan image
  run: |
    scripts/bootstrap-tools.sh
    python -m pip install -e .
    layersecops scan --image-tar image.tar \
      --format json,sarif --fail-on high --output-dir reports
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/report.sarif
```

## Development

The package has no third-party Python dependencies.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

Unit tests use fixture JSON and a synthetic docker-archive; they do not need
Docker or the external tools:

```bash
python -m unittest discover -s tests -t . -v
```

Covered: each scanner parser against saved JSON, docker-archive and OCI archive
parsing (including containerd-style `blobs/` layers), whiteout/opaque-directory
handling, every attribution confidence level, deduplication across scanners,
policy evaluation, config loading, and all four report writers.

For an end-to-end check:

```bash
scripts/bootstrap-tools.sh
python -m pip install -e .
docker pull alpine:3.20
docker save alpine:3.20 -o /tmp/alpine.tar
layersecops scan --image-tar /tmp/alpine.tar --format json,html,table --keep-raw
```

`scripts/extract-image.sh` saves an image and prints its layers without starting
a container:

```bash
scripts/extract-image.sh nginx:1.25 nginx.tar
scripts/extract-image.sh --inspect nginx.tar
```

## Container image

LayerSecOps ships a minimal, non-root container image for CI/CD pipelines. It
contains the four scanner binaries and the Python package, but no Docker daemon.

```bash
# Build locally
docker build -f docker/Dockerfile -t layersecops:latest .

# Bake the vulnerability databases into the image (faster, air-gapped runs)
docker build -f docker/Dockerfile --build-arg BAKE_DB=true -t layersecops:latest .

# Scan an exported image archive
docker run --rm \
  -v "$PWD:/work" -v "$PWD/reports:/reports" \
  layersecops:latest scan --image-tar /work/image.tar \
    --format json,sarif,html,metrics --output-dir /reports
```

The process exit code is the gate result (`0` pass, `1` policy failure,
`2` scan/tool failure, `3` bad usage), so `docker run` propagates failure to
the CI step automatically. See `examples/ci/` for GitHub Actions and GitLab CI
templates.

### Observability

- **Structured logs.** Set `LAYERSECOPS_LOG_FORMAT=json` (or pass
  `--log-format json`) to emit one JSON object per line on stderr, including a
  final `scan.result` event with counts, policy verdict, exit code, duration and
  report paths.
- **Prometheus metrics.** Add `metrics` to `--format` to write `report.prom`
  in Prometheus text exposition format: finding counts by severity/kind/source,
  per-layer counts and sizes, tool status and duration, scan duration, image
  size/efficiency, and the policy verdict. Upload it to your metrics backend or
  attach it as a pipeline artifact.
- **Raw artifacts.** `--keep-raw` copies every scanner's JSON and logs into
  `raw/` for forensics; `--sbom` copies the Syft SBOM. All reports are
  self-contained (no CDN, no network at render time).

## Limitations and design notes

- **Image-level validation.** Findings describe the image filesystem, not a
  running process. Runtime-only issues (mounted secrets, kernel settings) are
  out of scope.
- **Layer attribution is evidence-based.** Packages can be installed by one
  layer and later patched by another. The reported layer owns the final file;
  `introducedIndex` shows when the path first appeared.
- **Scope.** `--layer-scope squashed` (default) validates the filesystem the
  image will actually run. Use `all-layers` when you also care about packages
  that were installed and then removed in an earlier layer.
- **Package database paths** are weaker evidence than actual package files.
  They are labelled `db` rather than `exact`.
- **Multi-image archives.** Docker archives can contain more than one image;
  LayerSecOps scans the first manifest entry.
- **Compressed layers.** Gzip/bzip2/xz layer tars are supported by Python's
  `tarfile`. Zstandard-compressed layers require a Python build with zstd
  support; otherwise that layer's file list is skipped with a warning. Trivy,
  Grype and Syft can still scan the image itself.
- **Layer sizes** from `docker save` are uncompressed tar sizes; a live daemon
  inspect (`Size`) is preferred when available.
- **Database freshness.** LayerSecOps does not bundle vulnerability databases.
  Use `--offline` only when the tool caches are already populated.
- **Secret scanning is opt-in** and reports only the rule, path and severity,
  never the secret material.
