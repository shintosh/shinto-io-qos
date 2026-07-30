#!/usr/bin/env python3
"""Verify bounded metadata and contract facts for one published image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SOURCE = "https://github.com/shintosh/shinto-io-qos"
BUILDER_DIGEST = "sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651"
SBOM_DIGEST = "sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68"


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load(path: Path) -> object:
    return json.loads(path.read_text())


def flattened(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def marker_paths(value: object, marker: str, path: str) -> list[str]:
    matches: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if marker in str(key).lower():
                matches.append(child_path)
            matches.extend(marker_paths(child, marker, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(marker_paths(child, marker, f"{path}[{index}]"))
    elif marker in str(value).lower():
        matches.append(path)
    return matches


def verify(args: argparse.Namespace) -> None:
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest) is not None, "image digest is not exact")
    manifest_digest = "sha256:" + hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    require(manifest_digest == args.digest, "manifest bytes do not match requested digest")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is not None, "source revision is not exact")
    source_contract = args.contract.read_bytes()
    require(source_contract == args.embedded_contract.read_bytes(), "embedded runtime contract differs")
    contract_hash = hashlib.sha256(source_contract).hexdigest()
    provenance = load(args.provenance)
    sbom = load(args.sbom)
    image = load(args.image)
    provenance_text = flattened(provenance)
    sbom_text = flattened(sbom)
    image_text = flattened(image)
    require(len(provenance_text) > 100, "maximum provenance is empty")
    require("https://slsa.dev/provenance/v1" in provenance_text, "provenance predicate type differs")
    require('"parameters":true' in provenance_text and '"environment":true' in provenance_text and '"materials":true' in provenance_text, "maximum provenance completeness differs")
    require(SOURCE in provenance_text, "provenance source differs")
    require(args.source_revision in provenance_text, "provenance revision differs")
    require(BUILDER_DIGEST in provenance_text, "provenance lacks pinned Go builder")
    require(len(sbom_text) > 100 and "SPDX" in sbom_text.upper(), "SPDX SBOM is empty")
    require(SBOM_DIGEST in provenance_text or SBOM_DIGEST in sbom_text, "attestations lack pinned SBOM generator")
    require('"os":"linux"' in image_text.lower(), "image OS differs")
    require('"architecture":"amd64"' in image_text.lower(), "image architecture differs")
    require(SOURCE in image_text, "OCI source label differs")
    require(args.source_revision in image_text, "OCI revision label differs")
    require(contract_hash in image_text, "contract label differs")
    require('"io.shintosh.shinto-io-qos.base":"scratch"' in image_text, "scratch result differs")
    documents = (("provenance", provenance), ("sbom", sbom), ("image", image))
    for forbidden in ("github.com/xojigsx", "ghcr.io/xojigsx", "authorization", "password", "private key"):
        paths = [path for name, document in documents for path in marker_paths(document, forbidden, name)]
        require(not paths, f"published metadata contains forbidden marker: {forbidden} at {', '.join(paths[:5])}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--digest", required=True)
    parser.add_argument("--source-revision", required=True)
    for name in ("contract", "embedded-contract", "provenance", "sbom", "image", "manifest"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args)
    except (VerificationError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"published image verification failed: {error}", file=sys.stderr)
        return 1
    print("published image metadata valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
