#!/usr/bin/env python3
"""Run the version-matching and direct-call baselines on Set A."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETA = ROOT / "benchmarks" / "setA"
RAW = ROOT / "results" / "raw"
TABLES = ROOT / "results" / "tables"
JAVA = ROOT / ".tools" / "jdk17" / "bin" / "javap"
GRYPE = ROOT / ".tools" / "bin" / "grype"
TRIVY = ROOT / ".tools" / "bin" / "trivy"

TARGETS = {
    "log4j": {
        "cve": "CVE-2021-44228",
        "ghsa": "GHSA-jfh8-c2jp-5v3q",
        "javap": "org/apache/logging/log4j/core/net/JndiManager.lookup",
    },
    "commons": {
        "cve": "CVE-2022-42889",
        "ghsa": "GHSA-599f-7c49-w659",
        "javap": "org/apache/commons/text/StringSubstitutor.replace",
    },
    "snakeyaml": {
        "cve": "CVE-2022-1471",
        "ghsa": "GHSA-mjmj-j48q-9wg2",
        "javap": "org/yaml/snakeyaml/Yaml.load",
    },
}


def class_names(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    names = []
    for path in sorted(directory.rglob("*.class")):
        relative = path.relative_to(directory).with_suffix("")
        names.append(".".join(relative.parts))
    return names


def direct_call_detected(app_dir: Path, target: str) -> bool:
    dirs = [app_dir / "target" / "classes", app_dir / "target" / "test-classes"]
    entries = []
    for directory in dirs:
        entries.extend(class_names(directory))
    if not entries:
        return False
    classpath = ":".join(str(directory) for directory in dirs if directory.is_dir())
    for name in entries:
        completed = subprocess.run(
            [str(JAVA), "-c", "-p", "-classpath", classpath, name],
            text=True,
            capture_output=True,
            check=False,
        )
        if target in (completed.stdout or ""):
            return True
    return False


def grype_detected(sbom_path: Path, target: dict) -> bool:
    completed = subprocess.run(
        [str(GRYPE), f"sbom:{sbom_path}", "-o", "json", "-q"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return False
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    for match in document.get("matches", []):
        vulnerability = match.get("vulnerability", {})
        ids = {vulnerability.get("id", "")}
        ids.update(vulnerability.get("aliases") or [])
        if target["cve"] in ids or target["ghsa"] in ids:
            return True
    return False


def trivy_detected(app_dir: Path, target: dict) -> bool:
    completed = subprocess.run(
        [
            str(TRIVY),
            "fs",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--quiet",
            str(app_dir),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return False
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False
    for result in document.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            if vulnerability.get("VulnerabilityID") == target["cve"]:
                return True
    return False


def metrics(rows: list[dict], key: str) -> dict:
    tp = fp = fn = tn = 0
    for row in rows:
        expected = row["expected"] in ("Reachable", "PossiblyReachable")
        actual = row[key]
        if expected and actual:
            tp += 1
        elif expected and not actual:
            fn += 1
        elif not expected and actual:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main() -> int:
    manifest = json.loads((SETA / "manifest.json").read_text(encoding="utf-8"))
    rows = []
    for item in manifest:
        app_dir = SETA / item["app_dir"]
        library = item["library"].split("-")[0]
        library = "log4j" if library == "log4j" else library
        target = TARGETS[library]
        sbom = RAW / "sbom" / f"{item['id']}.cdx.json"
        row = {
            "app": item["id"],
            "library": library,
            "pattern": item["pattern"],
            "expected": item["expected"],
            "grype": grype_detected(sbom, target),
            "trivy": trivy_detected(app_dir, target),
            "direct_call": direct_call_detected(app_dir, target["javap"]),
        }
        rows.append(row)
        print(
            "[baseline] %-14s grype=%s trivy=%s direct=%s"
            % (row["app"], row["grype"], row["trivy"], row["direct_call"]),
            flush=True,
        )

    TABLES.mkdir(parents=True, exist_ok=True)
    with (TABLES / "baselines.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "grype": metrics(rows, "grype"),
        "trivy": metrics(rows, "trivy"),
        "direct_call": metrics(rows, "direct_call"),
        "positive_definition": "Reachable or PossiblyReachable",
    }
    (RAW / "baselines-metrics.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
