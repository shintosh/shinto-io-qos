#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts/verify-published-image.py"
REVISION = "1" * 40
DIGEST = "sha256:" + "2" * 64


class PublishedImageVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        contract = (ROOT / "contract/runtime.json").read_bytes()
        (self.root / "contract.json").write_bytes(contract)
        (self.root / "embedded.json").write_bytes(contract)
        contract_hash = hashlib.sha256(contract).hexdigest()
        self.provenance = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "source": "https://github.com/shintosh/shinto-io-qos",
            "revision": REVISION,
            "materials": [
                "sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651",
                "sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68",
            ],
            "metadata": {"buildInvocationId": "fixture", "completeness": {"parameters": True, "environment": True, "materials": True}},
        }
        self.sbom = {
            "spdxVersion": "SPDX-2.3",
            "name": "shinto-io-qos",
            "documentNamespace": "https://github.com/shintosh/shinto-io-qos/sbom/fixture",
            "packages": [{"name": "shinto-io-governor", "versionInfo": REVISION}],
        }
        self.image = {
            "os": "linux", "architecture": "amd64",
            "config": {"Labels": {
                "org.opencontainers.image.source": "https://github.com/shintosh/shinto-io-qos",
                "org.opencontainers.image.revision": REVISION,
                "io.shintosh.shinto-io-qos.contract-sha256": contract_hash,
            }},
        }

    def write(self, name: str, value: object) -> None:
        (self.root / name).write_text(json.dumps(value))

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        self.write("provenance.json", self.provenance)
        self.write("sbom.json", self.sbom)
        self.write("image.json", self.image)
        return subprocess.run([
            "python3", str(VERIFY), "--digest", DIGEST, "--source-revision", REVISION,
            "--contract", str(self.root / "contract.json"), "--embedded-contract", str(self.root / "embedded.json"),
            "--provenance", str(self.root / "provenance.json"), "--sbom", str(self.root / "sbom.json"),
            "--image", str(self.root / "image.json"),
        ], text=True, capture_output=True)

    def test_valid_metadata(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_contract_drift(self) -> None:
        (self.root / "embedded.json").write_text("{}\n")
        result = self.run_verifier()
        self.assertIn("embedded runtime contract differs", result.stderr)

    def test_rejects_wrong_revision(self) -> None:
        self.provenance["revision"] = "3" * 40
        result = self.run_verifier()
        self.assertIn("provenance revision differs", result.stderr)

    def test_rejects_missing_sbom(self) -> None:
        self.sbom = {}
        result = self.run_verifier()
        self.assertIn("SPDX SBOM is empty", result.stderr)

    def test_rejects_private_material(self) -> None:
        self.provenance["private"] = "github.com/xojigsx/shinto"
        result = self.run_verifier()
        self.assertIn("forbidden marker", result.stderr)
        self.assertIn("provenance.private", result.stderr)


if __name__ == "__main__":
    unittest.main()
