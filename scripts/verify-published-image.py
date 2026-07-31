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
            if marker in str(key).lower() and child not in (None, "", [], {}):
                matches.append(child_path)
            matches.extend(marker_paths(child, marker, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(marker_paths(child, marker, f"{path}[{index}]"))
    elif marker in str(value).lower():
        matches.append(path)
    return matches


def contains_sha256(value: object, digest: str) -> bool:
    digest_hex = digest.removeprefix("sha256:")
    if isinstance(value, dict):
        if value.get("sha256") == digest_hex:
            return True
        return any(contains_sha256(child, digest) for child in value.values())
    if isinstance(value, list):
        return any(contains_sha256(child, digest) for child in value)
    return value == digest


def platform_manifest_digest(manifest: object) -> str:
    require(isinstance(manifest, dict), "manifest index is not an object")
    matches = []
    for descriptor in manifest.get("manifests", []):
        if descriptor.get("platform") == {"os": "linux", "architecture": "amd64"}:
            matches.append(descriptor.get("digest"))
    require(len(matches) == 1 and re.fullmatch(r"sha256:[0-9a-f]{64}", str(matches[0])) is not None, "manifest lacks one Linux amd64 image")
    platform_digest = str(matches[0])
    attestations = [descriptor for descriptor in manifest.get("manifests", []) if descriptor.get("annotations", {}).get("vnd.docker.reference.digest") == platform_digest and descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"]
    require(len(attestations) == 1, "manifest lacks one attestation manifest for Linux amd64 image")
    return platform_digest


def verify(args: argparse.Namespace) -> None:
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest) is not None, "image digest is not exact")
    manifest_bytes = args.manifest.read_bytes()
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    require(manifest_digest == args.digest, "manifest bytes do not match requested digest")
    platform_digest = platform_manifest_digest(json.loads(manifest_bytes))
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_revision) is not None, "source revision is not exact")
    source_contract = args.contract.read_bytes()
    require(source_contract == args.embedded_contract.read_bytes(), "embedded runtime contract differs")
    contract_hash = hashlib.sha256(source_contract).hexdigest()
    provenance = load(args.provenance)
    sbom = load(args.sbom)
    image = load(args.image)
    require(isinstance(provenance, dict) and isinstance(provenance.get("SLSA"), dict), "provenance projection shape differs")
    require(isinstance(sbom, dict) and isinstance(sbom.get("SPDX"), dict), "SBOM projection shape differs")
    provenance_payload = provenance["SLSA"]
    sbom_payload = sbom["SPDX"]
    provenance_text = flattened(provenance_payload)
    sbom_text = flattened(sbom_payload)
    image_text = flattened(image)
    require(len(provenance_text) > 100, "maximum provenance is empty")
    build_definition = provenance_payload.get("buildDefinition", {})
    run_metadata = provenance_payload.get("runDetails", {}).get("metadata", {})
    completeness = run_metadata.get("buildkit_completeness", {})
    expected_completeness = {"request": True, "resolvedDependencies": False}
    observed_completeness = {
        key: completeness.get(key) if isinstance(completeness, dict) and isinstance(completeness.get(key), bool) else "non-boolean"
        for key in expected_completeness
    }
    require(completeness == expected_completeness, f"maximum provenance completeness differs; observed completeness={flattened(observed_completeness)}")
    require(build_definition.get("buildType") == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md", "provenance build type differs")
    build_config = build_definition.get("internalParameters", {}).get("buildConfig", {})
    require(isinstance(build_config.get("llbDefinition"), list) and len(build_config["llbDefinition"]) > 0, "maximum provenance lacks build definition")
    buildkit_metadata = run_metadata.get("buildkit_metadata", {})
    require(isinstance(buildkit_metadata.get("source"), dict) and buildkit_metadata["source"], "maximum provenance lacks source mapping")
    vcs = buildkit_metadata.get("vcs", {})
    require(vcs.get("source") == SOURCE, "provenance source differs")
    require(vcs.get("revision") == args.source_revision, "provenance revision differs")
    require(contains_sha256(provenance_payload, BUILDER_DIGEST), "provenance lacks pinned Go builder")
    require(len(sbom_text) > 100 and re.fullmatch(r"SPDX-[0-9.]+", str(sbom_payload.get("spdxVersion"))) is not None, "SPDX SBOM is empty")
    require(contains_sha256(provenance_payload, SBOM_DIGEST) or contains_sha256(sbom_payload, SBOM_DIGEST), "attestations lack pinned SBOM generator")
    require(isinstance(image, dict) and image.get("os") == "linux", "image OS differs")
    require(image.get("architecture") == "amd64", "image architecture differs")
    labels = image.get("config", {}).get("Labels", {})
    require(labels.get("org.opencontainers.image.source") == SOURCE, "OCI source label differs")
    require(labels.get("org.opencontainers.image.revision") == args.source_revision, "OCI revision label differs")
    require(labels.get("io.shintosh.shinto-io-qos.contract-sha256") == contract_hash, "contract label differs")
    require(labels.get("io.shintosh.shinto-io-qos.base") == "scratch", "scratch result differs")
    documents = (("provenance", provenance), ("sbom", sbom), ("image", image))
    for forbidden in (
        "github.com/xojigsx", "ghcr.io/xojigsx", "authorization", "bearer",
        "password", "private key", "token", "secret", "ghp_", "github_pat_",
        "aws_access_key_id", "postgres_dsn", "connection string",
    ):
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
