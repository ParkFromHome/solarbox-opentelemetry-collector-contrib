#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Run govulncheck, retaining failures except narrowly verified build-inapplicable reports.

GO-2026-4883 and GO-2026-4887 are unreviewed, whole-module Go database
entries. The upstream advisories affect the Docker *daemon* plugin code:
https://github.com/moby/moby/security/advisories/GHSA-pxq6-2prw-chj9
https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2

Collector uses Docker's client and API types, not the daemon. Classify these
two reports as not applicable ONLY while the exact reviewed SDK version is
used, the reports remain unreviewed, and the actual dependency graph contains
no Docker packages outside client/api or the reviewed jsonmessage/stdcopy
client-output helpers. A new report, version, package or
review status fails normally. This says nothing about a host Docker daemon.

GO-2026-5327 affects MongoDB's optional CGo GSSAPI (Kerberos) implementation:
https://github.com/advisories/GHSA-cp6g-7hqx-qxhp
The database marks mongo.Connect, even when the gssapi build tag is absent.
Keep driver v2.3.1 for the receiver's existing MongoDB 4.0 support: v2.4 drops
that server version. Classify only this exact version/report/entry point when
its authentication package is present and its GSSAPI implementation is absent
from the actual build dependency graph. Builds enabling GSSAPI still fail.
"""

import json
import subprocess
import sys

DAEMON_REPORTS = frozenset({"GO-2026-4883", "GO-2026-4887"})
DOCKER = "github.com/docker/docker"
MONGO = "go.mongodb.org/mongo-driver/v2"
GSSAPI_REPORT = "GO-2026-5327"
# Testcontainers uses these two client-output helpers for progress/log streams.
# Neither imports daemon/plugin code. Keep this list exact, never all of pkg/.
CLIENT_HELPERS = frozenset({DOCKER + "/pkg/jsonmessage", DOCKER + "/pkg/stdcopy"})


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
    return package in (DOCKER + "/client", DOCKER + "/api") or package.startswith(DOCKER + "/api/") or package in CLIENT_HELPERS


def classify(report, imports):
    configs = [m["config"] for m in report if "config" in m]
    if len(configs) != 1 or configs[0].get("scan_level") != "symbol" or configs[0].get("scan_mode") != "source":
        raise ValueError("expected one source/symbol govulncheck result")
    advisories = {m["osv"]["id"]: m["osv"] for m in report if "osv" in m}
    docker_imports = {p for p in imports if p == DOCKER or p.startswith(DOCKER + "/")}
    client_only = DOCKER + "/client" in docker_imports and all(map(client_package, docker_imports))
    gssapi_absent = MONGO + "/x/mongo/driver/auth" in imports and not any(
        p == MONGO + "/x/mongo/driver/auth/internal/gssapi"
        or p.startswith(MONGO + "/x/mongo/driver/auth/internal/gssapi/") for p in imports
    )
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
        optional_gssapi_only = (
            identifier == GSSAPI_REPORT
            and frame.get("module") == MONGO
            and frame.get("version") == "v2.3.1"
            and frame.get("package") == MONGO + "/mongo"
            and frame.get("function") == "Connect"
            and "CVE-2026-2303" in advisories[identifier].get("aliases", [])
            and gssapi_absent
        )
        (not_applicable if daemon_only or optional_gssapi_only else blocked).add(identifier)
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
    needs_imports = any(m.get("finding", {}).get("osv") in DAEMON_REPORTS | {GSSAPI_REPORT} for m in report)
    imports = set()
    if needs_imports:
        deps = subprocess.run(["go", "list", "-deps", "-f", "{{.ImportPath}}", *argv[1:]], text=True, stdout=subprocess.PIPE, check=True)
        imports = set(deps.stdout.splitlines())
    blocked, not_applicable, advisories = classify(report, imports)
    for identifier in sorted(blocked):
        print(f"Vulnerability {identifier}: {advisories[identifier].get('summary', '')}")
        print(f"  https://pkg.go.dev/vuln/{identifier}")
    for identifier in sorted(not_applicable):
        if identifier == GSSAPI_REPORT:
            print(f"NOT APPLICABLE {identifier}: MongoDB v2.3.1 GSSAPI implementation is absent from this build")
            continue
        print(f"NOT APPLICABLE {identifier}: verified Docker v28.5.2 client/API/output-helper imports; daemon plugin code is absent")
    print(f"Reachable vulnerabilities: {len(blocked)}; verified build-inapplicable reports: {len(not_applicable)}")
    return 3 if blocked else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"govulncheck classification failed: {exc}", file=sys.stderr)
        sys.exit(1)
