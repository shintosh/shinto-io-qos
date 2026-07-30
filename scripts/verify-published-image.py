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


def verify(args: argparse.Namespace) -> None:
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest) is not None, "image digest is not exact")
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
    for forbidden in ("github.com/xojigsx", "ghcr.io/xojigsx", "authorization", "password", "private key"):
        require(forbidden not in (provenance_text + sbom_text + image_text).lower(), f"published metadata contains forbidden marker: {forbidden}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--digest", required=True)
    parser.add_argument("--source-revision", required=True)
    for name in ("contract", "embedded-contract", "provenance", "sbom", "image"):
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
