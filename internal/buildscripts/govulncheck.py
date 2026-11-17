#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Run govulncheck, retaining failures except two verified daemon-only reports.

GO-2026-4883 and GO-2026-4887 are unreviewed, whole-module Go database
entries. The upstream advisories affect the Docker *daemon* plugin code:
https://github.com/moby/moby/security/advisories/GHSA-pxq6-2prw-chj9
https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2

Collector uses Docker's client and API types, not the daemon. Classify these
two reports as not applicable ONLY while the exact reviewed SDK version is
used, the reports remain unreviewed, and the actual dependency graph contains
no Docker packages outside client/api. A new report, version, package or
review status fails normally. This says nothing about a host Docker daemon.
"""

import json
import subprocess
import sys

DAEMON_REPORTS = frozenset({"GO-2026-4883", "GO-2026-4887"})
DOCKER = "github.com/docker/docker"


def messages(text):
    decoder = json.JSONDecoder()
    offset = 0
    while text[offset:].strip():
        offset += len(text[offset:]) - len(text[offset:].lstrip())
        message, offset = decoder.raw_decode(text, offset)
        if not isinstance(message, dict):
            raise ValueError("govulncheck returned a non-object message")
        yield message


def client_package(package):
    return package in (DOCKER + "/client", DOCKER + "/api") or package.startswith(DOCKER + "/api/")


def classify(report, imports):
    configs = [m["config"] for m in report if "config" in m]
    if len(configs) != 1 or configs[0].get("scan_level") != "symbol" or configs[0].get("scan_mode") != "source":
        raise ValueError("expected one source/symbol govulncheck result")
    advisories = {m["osv"]["id"]: m["osv"] for m in report if "osv" in m}
    docker_imports = {p for p in imports if p == DOCKER or p.startswith(DOCKER + "/")}
    client_only = DOCKER + "/client" in docker_imports and all(map(client_package, docker_imports))
    blocked, not_applicable = set(), set()
    for message in report:
        if "finding" not in message:
            continue
        finding = message["finding"]
        trace = finding.get("trace", [])
        if not trace:
            raise ValueError("finding has no trace")
        frame = trace[0]
        if not frame.get("function"):
            continue  # Same symbol-level policy as plain govulncheck.
        identifier = finding["osv"]
        if identifier not in advisories:
            raise ValueError("finding has no advisory")
        daemon_only = (
            identifier in DAEMON_REPORTS
            and frame.get("module") == DOCKER
            and frame.get("version") == "v28.5.2+incompatible"
            and client_package(frame.get("package", ""))
            and advisories[identifier].get("database_specific", {}).get("review_status") == "UNREVIEWED"
            and client_only
        )
        (not_applicable if daemon_only else blocked).add(identifier)
    # Never mask a report if any of its findings is outside the narrow exception.
    return blocked, not_applicable - blocked, advisories


def main(argv):
    if not argv:
        raise ValueError("expected govulncheck executable and package arguments")
    scan = subprocess.run([argv[0], "-json", *argv[1:]], text=True, stdout=subprocess.PIPE, check=False)
    if scan.returncode:
        print(scan.stdout)
        return scan.returncode
    report = list(messages(scan.stdout))
    needs_imports = any(m.get("finding", {}).get("osv") in DAEMON_REPORTS for m in report)
    imports = set()
    if needs_imports:
        deps = subprocess.run(["go", "list", "-deps", "-f", "{{.ImportPath}}", *argv[1:]], text=True, stdout=subprocess.PIPE, check=True)
        imports = set(deps.stdout.splitlines())
    blocked, not_applicable, advisories = classify(report, imports)
    for identifier in sorted(blocked):
        print(f"Vulnerability {identifier}: {advisories[identifier].get('summary', '')}")
        print(f"  https://pkg.go.dev/vuln/{identifier}")
    for identifier in sorted(not_applicable):
        print(f"NOT APPLICABLE {identifier}: verified Docker v28.5.2 client/API-only imports; daemon plugin code is absent")
    print(f"Reachable vulnerabilities: {len(blocked)}; verified daemon-only reports: {len(not_applicable)}")
    return 3 if blocked else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"govulncheck classification failed: {exc}", file=sys.stderr)
        sys.exit(1)
