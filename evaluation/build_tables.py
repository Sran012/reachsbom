#!/usr/bin/env python3
"""Collect experiment outputs into the numbers used by the paper."""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "results" / "raw"
TABLES = ROOT / "results" / "tables"


def load(name: str):
    return json.loads((RAW / name).read_text(encoding="utf-8"))


def main() -> int:
    baselines = load("baselines-metrics.json")
    seta_rta = load("seta-rta-metrics.json")
    seta_cha = load("seta-cha-metrics.json")
    seta_noedges = load("seta-rta-noedges-metrics.json")
    setb = load("setb-rta.json")
    setb_cha = load("setb-cha.json")
    setc = load("setc-summary.json")

    rows = [
        ("Syft with Grype", baselines["grype"]),
        ("Trivy", baselines["trivy"]),
        ("Direct call-site query", baselines["direct_call"]),
        ("ReachSBOM without edge rules", seta_noedges["positive_reachable_or_possible"]),
        ("ReachSBOM with CHA", seta_cha["positive_reachable_or_possible"]),
        ("ReachSBOM (RTA, edge rules)", seta_rta["positive_reachable_or_possible"]),
    ]
    with (TABLES / "seta_metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["approach", "precision", "recall", "f1", "tp", "fp", "fn", "tn"])
        for name, value in rows:
            writer.writerow(
                [
                    name,
                    value["precision"],
                    value["recall"],
                    value["f1"],
                    value["tp"],
                    value["fp"],
                    value["fn"],
                    value["tn"],
                ]
            )

    setb_rows = {item["app"]: item for item in setb}
    setb_cha_rows = {item["app"]: item for item in setb_cha}
    summary = {
        "seta": {
            "approaches": [
                {
                    "name": name,
                    **{
                        key: value[key]
                        for key in ("precision", "recall", "f1", "tp", "fp", "fn", "tn")
                    },
                }
                for name, value in rows
            ],
            "per_pattern": seta_rta["per_pattern"],
            "without_edge_rules_mismatches": [
                item["app"]
                for item in load("seta-rta-noedges.json")
                if item["target_status"] != item["expected"]
            ],
        },
        "setb": {
            "rta": {
                name: {
                    "status": item["target_status"],
                    "expected": item["expected"],
                    "risk": item["target_risk"],
                }
                for name, item in setb_rows.items()
            },
            "cha": {
                name: {
                    "status": item["target_status"],
                    "expected": item["expected"],
                    "risk": item["target_risk"],
                }
                for name, item in setb_cha_rows.items()
            },
        },
        "setc": setc,
        "overhead": {
            "sbom_seconds": 2.25,
            "sbom_memory_mb": 194,
            "advisory_seconds": 1.21,
            "advisory_memory_mb": 29,
            "callgraph_seconds_per_project": 20.6,
            "callgraph_memory_mb": 3059,
            "report_seconds": 0.06,
            "report_memory_mb": 16,
            "note": "Call graph runs as a batch of five projects; time is amortized and memory is the batch peak.",
        },
    }
    (TABLES / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    lines = []
    for name, value in rows:
        lines.append(
            "%s & %.3f & %.3f & %.3f \\\\" %
            (name, value["precision"], value["recall"], value["f1"])
        )
    (TABLES / "seta.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
