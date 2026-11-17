# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import copy
import json
import unittest
from unittest.mock import patch
import subprocess

import govulncheck


class GovulncheckTest(unittest.TestCase):
    def setUp(self):
        self.report = [
            {"config": {"scan_level": "symbol", "scan_mode": "source"}},
            {"osv": {"id": "GO-2026-4887", "database_specific": {"review_status": "UNREVIEWED"}}},
            {"finding": {"osv": "GO-2026-4887", "trace": [{
                "module": govulncheck.DOCKER, "version": "v28.5.2+incompatible",
                "package": govulncheck.DOCKER + "/client", "function": "NewClientWithOpts",
            }]}},
        ]
        self.imports = {govulncheck.DOCKER + "/client", govulncheck.DOCKER + "/api/types/container"}

    def test_client_only_is_not_applicable(self):
        blocked, exempt, _ = govulncheck.classify(self.report, self.imports)
        self.assertEqual(blocked, set())
        self.assertEqual(exempt, {"GO-2026-4887"})

    def test_reviewed_client_output_helpers_are_not_applicable(self):
        for package in govulncheck.CLIENT_HELPERS:
            report = copy.deepcopy(self.report)
            report[2]["finding"]["trace"][0]["package"] = package
            blocked, exempt, _ = govulncheck.classify(report, self.imports | {package})
            self.assertFalse(blocked)
            self.assertEqual(exempt, {"GO-2026-4887"})

    def test_daemon_or_unknown_import_blocks(self):
        for package in ("daemon", "pkg/authorization", "plugin", "pkg/unknown", "pkg/stdcopy/new", "new-package"):
            with self.subTest(package=package):
                blocked, _, _ = govulncheck.classify(self.report, self.imports | {govulncheck.DOCKER + "/" + package})
                self.assertEqual(blocked, {"GO-2026-4887"})

    def test_version_review_and_unknown_report_block(self):
        mutations = [
            (2, lambda m: m["finding"]["trace"][0].update(version="v28.5.3+incompatible")),
            (1, lambda m: m["osv"]["database_specific"].update(review_status="REVIEWED")),
            (2, lambda m: m["finding"]["trace"][0].update(package=govulncheck.DOCKER + "/plugin")),
        ]
        for index, mutate in mutations:
            report = copy.deepcopy(self.report)
            mutate(report[index])
            self.assertEqual(govulncheck.classify(report, self.imports)[0], {"GO-2026-4887"})
        self.report[1]["osv"]["id"] = "GO-2026-9999"
        self.report[2]["finding"]["osv"] = "GO-2026-9999"
        self.assertEqual(govulncheck.classify(self.report, self.imports)[0], {"GO-2026-9999"})

    def test_missing_import_evidence_blocks(self):
        self.assertEqual(govulncheck.classify(self.report, set())[0], {"GO-2026-4887"})

    def test_any_server_finding_blocks_same_report(self):
        server = copy.deepcopy(self.report[2])
        server["finding"]["trace"][0]["package"] = govulncheck.DOCKER + "/plugin"
        self.report.append(server)
        blocked, exempt, _ = govulncheck.classify(self.report, self.imports)
        self.assertEqual(blocked, {"GO-2026-4887"})
        self.assertFalse(exempt)

    def test_module_only_findings_remain_nonblocking(self):
        del self.report[2]["finding"]["trace"][0]["function"]
        self.assertEqual(govulncheck.classify(self.report, set())[:2], (set(), set()))

    def test_invalid_or_truncated_results_fail(self):
        with self.assertRaises(ValueError):
            govulncheck.classify([], self.imports)
        with self.assertRaises(ValueError):
            list(govulncheck.messages('{"config":'))
        with self.assertRaises(ValueError):
            list(govulncheck.messages('[]'))
        with self.assertRaises(ValueError):
            govulncheck.classify([{"config": {"scan_level": "package"}}], self.imports)

    def test_tool_failure_is_preserved(self):
        with patch("govulncheck.subprocess.run", return_value=subprocess.CompletedProcess([], 7, "scan failed")):
            self.assertEqual(govulncheck.main(["govulncheck", "./..."]), 7)

    def test_mongodb_optional_gssapi_build(self):
        report = [
            {"config": {"scan_level": "symbol", "scan_mode": "source"}},
            {"osv": {"id": govulncheck.GSSAPI_REPORT, "aliases": ["CVE-2026-2303"]}},
            {"finding": {"osv": govulncheck.GSSAPI_REPORT, "trace": [{
                "module": govulncheck.MONGO, "version": "v2.3.1",
                "package": govulncheck.MONGO + "/mongo", "function": "Connect",
            }]}},
        ]
        imports = {govulncheck.MONGO + "/x/mongo/driver/auth"}
        self.assertEqual(govulncheck.classify(report, imports)[:2], (set(), {govulncheck.GSSAPI_REPORT}))
        for packages in (set(), imports | {govulncheck.MONGO + "/x/mongo/driver/auth/internal/gssapi"}):
            self.assertEqual(govulncheck.classify(report, packages)[0], {govulncheck.GSSAPI_REPORT})
        for key, value in (("version", "v2.3.2"), ("function", "NewClient"), ("package", govulncheck.MONGO + "/other")):
            altered = copy.deepcopy(report)
            altered[2]["finding"]["trace"][0][key] = value
            self.assertEqual(govulncheck.classify(altered, imports)[0], {govulncheck.GSSAPI_REPORT})
        report[1]["osv"]["aliases"] = []
        self.assertEqual(govulncheck.classify(report, imports)[0], {govulncheck.GSSAPI_REPORT})

    def test_stream_round_trip(self):
        self.assertEqual(list(govulncheck.messages("\n".join(map(json.dumps, self.report)))), self.report)


if __name__ == "__main__":
    unittest.main()
