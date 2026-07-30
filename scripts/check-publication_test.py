#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-publication.py"


class PublicationContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Path(self.temp.name) / "repo"
        shutil.copytree(ROOT, self.fixture, ignore=shutil.ignore_patterns(".git", "__pycache__"))

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CHECKER), "--root", str(self.fixture)],
            text=True,
            capture_output=True,
        )

    def mutate(self, path: str, old: str, new: str) -> None:
        target = self.fixture / path
        text = target.read_text()
        self.assertIn(old, text)
        target.write_text(text.replace(old, new, 1))

    def test_valid_repository(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_foreign_go_dependency(self) -> None:
        self.mutate("cmd/shinto-io-governor/main.go", '"flag"', '"flag"\n\t"example.com/private/pkg"')
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Go source import parse reported errors", result.stderr)

    def test_rejects_module_companion(self) -> None:
        (self.fixture / "go.sum").write_text("unexpected\n")
        result = self.run_checker()
        self.assertIn("forbidden module companion", result.stderr)

    def test_rejects_go_mod_directive(self) -> None:
        target = self.fixture / "go.mod"
        target.write_text(target.read_text() + "\nrequire example.com/module v1.0.0\n")
        result = self.run_checker()
        self.assertIn("go.mod must contain only", result.stderr)

    def test_rejects_mutable_builder(self) -> None:
        path = "cmd/shinto-io-governor/Dockerfile.release"
        self.mutate(path, "golang:1.26.5-bookworm@sha256:", "golang:1.26.5-bookworm#sha256:")
        result = self.run_checker()
        self.assertIn("builder image must be exact and pinned", result.stderr)

    def test_rejects_remote_frontend(self) -> None:
        target = self.fixture / "cmd/shinto-io-governor/Dockerfile.release"
        target.write_text("# syntax=docker/dockerfile:1\n" + target.read_text())
        result = self.run_checker()
        self.assertIn("remote Dockerfile frontend", result.stderr)

    def test_rejects_networked_build_step(self) -> None:
        self.mutate("cmd/shinto-io-governor/Dockerfile.release", "RUN --network=none ", "RUN ")
        result = self.run_checker()
        self.assertIn("every Dockerfile RUN", result.stderr)

    def test_rejects_arg_selected_base(self) -> None:
        self.mutate("cmd/shinto-io-governor/Dockerfile.release", "FROM scratch", "ARG FINAL=scratch\nFROM ${FINAL}")
        result = self.run_checker()
        self.assertIn("final image must use scratch", result.stderr)

    def test_rejects_broad_copy(self) -> None:
        target = self.fixture / "cmd/shinto-io-governor/Dockerfile.release"
        target.write_text(target.read_text() + "\nCOPY cmd/shinto-io-governor/ /unexpected/\n")
        result = self.run_checker()
        self.assertIn("Dockerfile COPY allowlist differs", result.stderr)

    def test_rejects_secret_mount(self) -> None:
        self.mutate("cmd/shinto-io-governor/Dockerfile.release", "RUN --network=none ", "RUN --network=none --mount=type=secret ")
        result = self.run_checker()
        self.assertIn("forbidden Docker build input", result.stderr)

    def test_rejects_broad_context_allow(self) -> None:
        target = self.fixture / ".dockerignore"
        target.write_text(target.read_text() + "!cmd/**/*.go\n")
        result = self.run_checker()
        self.assertIn("allow rules must be explicit", result.stderr)

    def test_rejects_mutable_action(self) -> None:
        self.mutate(".github/workflows/release.yml", "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803", "actions/checkout@v4")
        result = self.run_checker()
        self.assertIn("workflow lacks required contract", result.stderr)

    def test_rejects_unapproved_action(self) -> None:
        target = self.fixture / ".github/workflows/release.yml"
        target.write_text(target.read_text() + "\n      - uses: vendor/action@1111111111111111111111111111111111111111\n")
        result = self.run_checker()
        self.assertIn("unapproved action", result.stderr)

    def test_rejects_self_hosted_runner(self) -> None:
        self.mutate(".github/workflows/release.yml", "runs-on: ubuntu-24.04", "runs-on: self-hosted")
        result = self.run_checker()
        self.assertIn("workflow lacks required contract", result.stderr)

    def test_rejects_deployment_command(self) -> None:
        target = self.fixture / ".github/workflows/release.yml"
        target.write_text(target.read_text() + "\n# kubectl apply -f deploy.yaml\n")
        result = self.run_checker()
        self.assertIn("workflow contains forbidden contract", result.stderr)

    def test_rejects_external_cache(self) -> None:
        target = self.fixture / ".github/workflows/release.yml"
        target.write_text(target.read_text() + "\n# --cache-to type=registry,ref=example/cache\n")
        result = self.run_checker()
        self.assertIn("workflow contains forbidden contract", result.stderr)

    def test_rejects_dispatch_input(self) -> None:
        self.mutate(".github/workflows/release.yml", "  workflow_dispatch:\n", "  workflow_dispatch:\n    inputs:\n")
        result = self.run_checker()
        self.assertIn("workflow dispatch inputs are forbidden", result.stderr)

    def test_rejects_extra_token_use(self) -> None:
        target = self.fixture / ".github/workflows/release.yml"
        target.write_text(target.read_text() + "\n# ${{ github.token }}\n")
        result = self.run_checker()
        self.assertIn("workflow token use differs", result.stderr)

    def test_rejects_nonempty_rootfs_placeholder(self) -> None:
        (self.fixture / "cmd/shinto-io-governor/rootfs/host-cgroup/kubepods/io.max").write_text("max")
        result = self.run_checker()
        self.assertIn("rootfs placeholders must be empty", result.stderr)


if __name__ == "__main__":
    unittest.main()
