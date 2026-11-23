#!/usr/bin/env bash
# Save an image without starting a container and list its layers.
#
# Usage:
#   scripts/extract-image.sh nginx:1.25 [image.tar]
#   scripts/extract-image.sh --inspect image.tar
set -euo pipefail

if [[ "${1:-}" == "--inspect" ]]; then
  ARCHIVE="${2:?usage: extract-image.sh --inspect image.tar}"
else
  IMAGE="${1:?usage: extract-image.sh IMAGE [ARCHIVE]}"
  ARCHIVE="${2:-image.tar}"
  command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
  echo "Saving ${IMAGE} to ${ARCHIVE}"
  docker save -o "${ARCHIVE}" "${IMAGE}"
fi

[[ -f "${ARCHIVE}" ]] || { echo "Archive not found: ${ARCHIVE}" >&2; exit 2; }

if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi

echo ""
echo "Archive: ${ARCHIVE} ($(du -h "${ARCHIVE}" | cut -f1))"
"${PYTHON}" - "${ARCHIVE}" <<'PY'
import json
import sys
import tarfile

path = sys.argv[1]
with tarfile.open(path, "r:*") as tf:
    names = set(tf.getnames())
    if "manifest.json" in names:
        manifest = json.load(tf.extractfile("manifest.json"))
        entry = manifest[0]
        print(f"Format:  docker-archive ({len(manifest)} image(s))")
        print(f"Tags:    {', '.join(entry.get('RepoTags') or ['-'])}")
        print("Layers:")
        for index, layer in enumerate(entry.get("Layers") or []):
            print(f"  [{index}] {layer}")
    elif "index.json" in names:
        index = json.load(tf.extractfile("index.json"))
        descriptor = (index.get("manifests") or [{}])[0]
        digest = descriptor.get("digest") or ""
        algorithm, _, value = digest.partition(":")
        manifest_path = f"blobs/{algorithm}/{value}"
        manifest = json.load(tf.extractfile(manifest_path))
        annotation = (descriptor.get("annotations") or {}).get(
            "org.opencontainers.image.ref.name"
        )
        print("Format:  oci-archive")
        print(f"Tags:    {annotation or '-'}")
        print("Layers:")
        for position, layer in enumerate(manifest.get("layers") or []):
            print(
                f"  [{position}] {layer.get('digest')} "
                f"({layer.get('mediaType', 'unknown')})"
            )
    else:
        print("Format:  unknown (no manifest.json or index.json)")
PY
