#!/usr/bin/env python3
"""Fail-closed source and publication contract for shinto-io-qos."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MODULE = "github.com/shintosh/shinto-io-qos"
PRIVATE_MARKERS = ("github.com/xojigsx", "ghcr.io/xojigsx", "shinto-bot@", "BEGIN PRIVATE KEY")
ROOTFS = {
    "host-cgroup/kubepods/io.max",
    "host-cgroup/kubepods/io.stat",
    "host-cgroup/podruntime/etcd/io.latency",
    "host-cgroup/podruntime/etcd/io.stat",
    "var/run/shinto-io-governor.prom",
}
GO_FILES = ("main.go", "governor.go", "governor_test.go", "metrics.go", "metrics_test.go")
PINNED_BUILDER = "docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651"
PINNED_BUILDKIT = "docker.io/moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
PINNED_SBOM = "docker.io/docker/buildkit-syft-scanner@sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68"
PINNED_CHECKOUT = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"


class ContractError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def read(root: Path, name: str) -> str:
    path = root / name
    require(path.is_file() and not path.is_symlink(), f"missing regular file: {name}")
    return path.read_text(encoding="utf-8")


def check_go(root: Path) -> None:
    go_mod = read(root, "go.mod")
    require(go_mod == f"module {MODULE}\n\ngo 1.26.5\n", "go.mod must contain only the exact module and Go version")
    for name in ("go.sum", "go.work", "vendor", ".gitmodules"):
        require(not (root / name).exists(), f"forbidden module companion: {name}")
    actual_go_files = tuple(path.name for path in sorted((root / "cmd/shinto-io-governor").glob("*.go")))
    require(set(actual_go_files) == set(GO_FILES), "Go source inventory differs")
    source = "\n".join(read(root, f"cmd/shinto-io-governor/{name}") for name in GO_FILES)
    require(not any(marker in source for marker in PRIVATE_MARKERS), "Go source contains a private marker")
    environment = os.environ.copy()
    environment.update({"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local"})
    syntax = subprocess.run(
        ["go", "list", "-e", "-json", "./cmd/shinto-io-governor"],
        cwd=root, env=environment, text=True, capture_output=True,
    )
    require(syntax.returncode == 0, f"Go source import parse failed: {syntax.stderr.strip()}")
    package = json.loads(syntax.stdout)
    require(not package.get("Error") and not package.get("DepsErrors"), "Go source import parse reported errors")
    result = subprocess.run(
        ["go", "list", "-deps", "-json", "./..."],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
    )
    require(result.returncode == 0, f"offline go list failed: {result.stderr.strip()}")
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(result.stdout):
        while offset < len(result.stdout) and result.stdout[offset].isspace():
            offset += 1
        if offset == len(result.stdout):
            break
        package, offset = decoder.raw_decode(result.stdout, offset)
        import_path = package.get("ImportPath", "")
        require(package.get("Standard") is True or import_path.startswith(MODULE), f"foreign Go dependency: {import_path}")


def check_contract(root: Path) -> None:
    raw = read(root, "contract/runtime.json")
    require(raw.endswith("\n") and not raw.endswith("\n\n"), "runtime contract must end with one newline")
    contract = json.loads(raw)
    expected_files = [
        {"name": "workload_io_max", "container_path": "/host-cgroup/kubepods/io.max", "access": "read_write", "kind": "file"},
        {"name": "workload_io_stat", "container_path": "/host-cgroup/kubepods/io.stat", "access": "read_only", "kind": "file"},
        {"name": "etcd_io_latency", "container_path": "/host-cgroup/podruntime/etcd/io.latency", "access": "read_write", "kind": "file"},
        {"name": "etcd_io_stat", "container_path": "/host-cgroup/podruntime/etcd/io.stat", "access": "read_only", "kind": "file"},
        {"name": "governor_metrics", "container_path": "/var/run/shinto-io-governor.prom", "access": "read_write", "kind": "file_or_create"},
    ]
    expected = {
        "schema_version": 1,
        "platform": {"os": "linux", "architecture": "amd64"},
        "command": {"name": "shinto-io-governor", "entrypoint": "/shinto-io-governor", "modes": ["observe", "enforce", "clear"]},
        "files": expected_files,
        "metrics_family_prefix": "shinto_io_governor_",
    }
    require(contract == expected, "runtime contract differs")
    rootfs = root / "cmd/shinto-io-governor/rootfs"
    actual = {str(path.relative_to(rootfs)) for path in rootfs.rglob("*") if path.is_file()}
    require(actual == ROOTFS, "rootfs file inventory differs")
    require(all((rootfs / name).stat().st_size == 0 for name in ROOTFS), "rootfs placeholders must be empty")


def check_docker(root: Path) -> None:
    dockerfile = read(root, "cmd/shinto-io-governor/Dockerfile.release")
    require("# syntax=" not in dockerfile, "remote Dockerfile frontend is forbidden")
    require(f"FROM {PINNED_BUILDER} AS build" in dockerfile, "builder image must be exact and pinned")
    require(re.search(r"(?m)^FROM scratch$", dockerfile) is not None, "final image must use scratch")
    require("ENTRYPOINT [\"/shinto-io-governor\"]" in dockerfile, "entrypoint differs")
    require("USER 0:0" in dockerfile, "final user must be explicit")
    require("io.shintosh.shinto-io-qos.contract-sha256" in dockerfile, "contract label is missing")
    require('LABEL io.shintosh.shinto-io-qos.base="scratch"' in dockerfile, "scratch result label is missing")
    from_lines = [line.strip() for line in dockerfile.splitlines() if line.strip().startswith("FROM ")]
    require(from_lines == [f"FROM {PINNED_BUILDER} AS build", "FROM scratch"], "Dockerfile stages differ")
    expected_copies = {
        "COPY go.mod ./",
        "COPY contract/runtime.json ./contract/runtime.json",
        *(f"COPY cmd/shinto-io-governor/{name} ./cmd/shinto-io-governor/{name}" for name in GO_FILES),
        "COPY --from=build /out/shinto-io-governor /shinto-io-governor",
        "COPY contract/runtime.json /shinto-io-qos-runtime-contract.json",
        *(f"COPY cmd/shinto-io-governor/rootfs/{name} /{name}" for name in ROOTFS),
    }
    actual_copies = {line.strip() for line in dockerfile.splitlines() if line.strip().startswith("COPY ")}
    require(actual_copies == expected_copies, "Dockerfile COPY allowlist differs")
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if stripped.startswith("RUN "):
            require(stripped.startswith("RUN --network=none "), "every Dockerfile RUN must disable networking")
        if stripped.startswith(("RUN ", "COPY ", "ADD ")):
            require(not re.search(r"--mount=type=(secret|ssh)|--network=host|https?://", stripped), "forbidden Docker build input")
        if stripped.startswith("ADD "):
            raise ContractError("Dockerfile ADD is forbidden")
    ignore = read(root, ".dockerignore").splitlines()
    require(ignore and ignore[0] == "**", ".dockerignore must deny everything first")
    require(all(not line.startswith("!") or "*" not in line for line in ignore[1:]), ".dockerignore allow rules must be explicit")
    allowed_files = {"go.mod", "contract/runtime.json", "cmd/shinto-io-governor/Dockerfile.release"}
    allowed_files.update(f"cmd/shinto-io-governor/{name}" for name in GO_FILES)
    allowed_files.update(f"cmd/shinto-io-governor/rootfs/{name}" for name in ROOTFS)
    require({line[1:] for line in ignore[1:] if line.startswith("!") and not line.endswith("/")} == allowed_files, ".dockerignore file allowlist differs")


def check_workflow(root: Path) -> None:
    workflow = read(root, ".github/workflows/release.yml")
    for required in (
        PINNED_CHECKOUT, PINNED_BUILDKIT, PINNED_SBOM, "runs-on: ubuntu-24.04",
        "github.ref == 'refs/heads/main'", "persist-credentials: false", "contents: read",
        "packages: write", "cancel-in-progress: false", "--attest type=provenance,mode=max",
        "ghcr.io/shintosh/shinto-io-qos:${GITHUB_SHA}",
    ):
        require(required in workflow, f"workflow lacks required contract: {required}")
    validation_contract = (
        "Provision pinned Go validation toolchain",
        f'builder_image="{PINNED_BUILDER}"',
        'docker pull "${builder_image}"',
        'docker create "${builder_image}"',
        'docker cp "${validation_container}:/usr/local/go/." "${RUNNER_TEMP}/go"',
        '"${RUNNER_TEMP}/go/bin/go" version',
        'echo "GOROOT=${RUNNER_TEMP}/go" >> "${GITHUB_ENV}"',
        'echo "${RUNNER_TEMP}/go/bin" >> "${GITHUB_PATH}"',
    )
    require(all(fragment in workflow for fragment in validation_contract), "workflow lacks pinned validation toolchain")
    require(workflow.index("Provision pinned Go validation toolchain") < workflow.index("Validate committed source"), "validation toolchain must precede source checks")
    for forbidden in ("self-hosted", "arc-runner", "pull_request", "push:", "schedule:", "curl ", "wget ", "gh ", "apt-get", "apk ", "yum ", "dnf ", "brew ", "kubectl", "talosctl", "ssh ", "release-all", "promote-stable", "--cache-to", "--cache-from", "--allow-insecure-entitlement", "--network=host", "--secret", "--ssh"):
        require(forbidden not in workflow, f"workflow contains forbidden contract: {forbidden}")
    for use in re.findall(r"(?m)^\s*- uses:\s*(\S+)", workflow):
        require(use == PINNED_CHECKOUT, f"unapproved action: {use}")
    require(len(re.findall(r"(?m)^\s*- uses:\s*", workflow)) == 1, "workflow must contain one checkout action")
    require(len(re.findall(r"(?m)^permissions:$", workflow)) == 1, "workflow permissions must have one owner")
    permission_match = re.search(r"(?ms)^permissions:\n((?:  [^\n]+\n)+)", workflow)
    require(permission_match is not None and permission_match.group(1).splitlines() == ["  contents: read", "  packages: write"], "workflow permissions differ")
    require(workflow.count("${{ github.token }}") == 1, "workflow token use differs")
    require(re.search(r"\$\{\{\s*secrets\.", workflow, re.IGNORECASE) is None, "extra workflow secrets are forbidden")
    require("docker login ghcr.io" in workflow, "workflow token must be limited to GHCR login")
    require("repository:" not in workflow, "workflow cannot check out another repository")
    require(re.search(r"(?m)^\s+inputs:\s*$", workflow) is None, "workflow dispatch inputs are forbidden")
    require(workflow.count("ref: ${{ github.sha }}") == 1, "workflow checkout ref differs")
    allowed_public_images = {PINNED_BUILDER, PINNED_BUILDKIT, PINNED_SBOM}
    referenced_images = set(re.findall(r"docker\.io/[A-Za-z0-9_./:@-]+", workflow))
    require(referenced_images == allowed_public_images, "workflow public image allowlist differs")


def check_private_markers(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.name in {"check-publication.py", "verify-published-image.py"} or path.name.endswith("_test.py"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        require(not any(marker in text for marker in PRIVATE_MARKERS), f"private marker in {path.relative_to(root)}")


def check(root: Path) -> None:
    check_go(root)
    check_contract(root)
    check_docker(root)
    check_workflow(root)
    check_private_markers(root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        check(args.root.resolve())
    except (ContractError, KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"publication contract failed: {error}", file=sys.stderr)
        return 1
    print("publication contract valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
