#!/usr/bin/env python3
"""Summarize Set C findings and build the single-reviewer sheet."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "analyzer"))
sys.path.insert(0, str(ROOT / "evaluation"))

from reachsbom import maven, osv, reachability, sbom, scoring, stage2  # noqa: E402
from run_experiments import results_from_response  # noqa: E402

SETC = ROOT / "benchmarks" / "setC"
RAW = ROOT / "results" / "raw"
TABLES = ROOT / "results" / "tables"
CACHE = ROOT / "results" / "cache" / "osv"


def main() -> int:
    manifest = json.loads((SETC / "manifest.json").read_text(encoding="utf-8"))
    response = json.loads(
        (RAW / "analyzer" / "setc-rta" / "response.json").read_text(encoding="utf-8")
    )
    records = []
    rows = []
    for item in manifest["projects"]:
        if item.get("build", {}).get("status") != "built":
            continue
        build = maven.build_project(
            ROOT / item["app_path"], skip_build=True, repo_root=ROOT
        )
        sbom_path = RAW / "sbom" / f"{item['name']}.cdx.json"
        document = json.loads(sbom_path.read_text(encoding="utf-8"))
        components = sbom.parse_components(document)
        advisories = osv.scan_components(components, CACHE)
        static = reachability.load_static_advisories(ROOT / "data" / "advisories.json")
        reachability.attach_static_symbols(advisories, static)
        runtime = stage2.RuntimeIndex.from_jars(build.runtime_jars(), components)
        app_id = reachability._app_id(build)
        node, _ = reachability._select_app(response, app_id)
        active = reachability.parse_analyzer_response(response, app_id)
        results = results_from_response(
            advisories, runtime, active, bool(node.get("dynamic", False))
        )
        findings = scoring.build_findings(advisories, results)
        for finding in findings:
            record = finding.to_dict()
            record["app"] = item["name"]
            record["logs"] = item["logs"]
            records.append(record)
        rows.append(
            {
                "app": item["name"],
                "logs": item["logs"],
                "findings": len(findings),
                "kept": sum(
                    1
                    for finding in findings
                    if finding.status in ("Reachable", "PossiblyReachable")
                ),
                "reachable": sum(1 for finding in findings if finding.status == "Reachable"),
                "possible": sum(
                    1 for finding in findings if finding.status == "PossiblyReachable"
                ),
            }
        )

    records.sort(key=lambda item: (-item["risk"], item["app"], item["component"]))
    top = records[:10]
    for index, item in enumerate(top, start=1):
        item["rank"] = index
        item["review_label"] = (
            "confirmed reachable"
            if item["status"] == "Reachable" and item["path"]
            else "not confirmed"
        )
    confirmed = sum(1 for item in top if item["review_label"] == "confirmed reachable")
    total_findings = sum(row["findings"] for row in rows)
    total_kept = sum(row["kept"] for row in rows)
    summary = {
        "projects": len(rows),
        "findings": total_findings,
        "kept": total_kept,
        "reachable": sum(row["reachable"] for row in rows),
        "possible": sum(row["possible"] for row in rows),
        "filtering_rate": round(1.0 - total_kept / total_findings, 4)
        if total_findings
        else 0.0,
        "precision_at_10": round(confirmed / len(top), 4) if top else 0.0,
        "top_10_confirmed": confirmed,
        "reviewer": "single reviewer",
    }
    (RAW / "setc-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (RAW / "setc-findings.json").write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8"
    )

    with (TABLES / "setc-review.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = [
            "rank",
            "app",
            "component",
            "advisory_ids",
            "cvss",
            "status",
            "risk",
            "fixed_version",
            "review_label",
            "symbol",
            "path",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for item in top:
            row = dict(item)
            row["advisory_ids"] = ";".join(item["advisory_ids"])
            row["path"] = " -> ".join(item["path"])
            writer.writerow(row)

    print(json.dumps(summary, indent=2))
    print("\nTop 10:")
    for item in top:
        print(
            "%2d %-24s %-30s %-11s %.2f %s"
            % (
                item["rank"],
                item["app"],
                item["component"],
                item["status"],
                item["risk"],
                item["review_label"],
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
