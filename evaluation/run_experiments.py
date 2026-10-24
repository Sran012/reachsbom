#!/usr/bin/env python3
"""Run the ReachSBOM benchmark sets and write raw records and tables."""

from __future__ import annotations

import argparse
import csv
import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "analyzer"))

from reachsbom import maven, osv, reachability, sbom, scoring, stage2  # noqa: E402
from reachsbom.models import (  # noqa: E402
    ProjectBuild,
    SymbolResult,
    base_purl,
    status_rank,
)
from reachsbom.reachability import _method_result  # noqa: E402


RAW = ROOT / "results" / "raw"
TABLES = ROOT / "results" / "tables"
WORK = ROOT / "results" / "work"
CACHE = ROOT / "results" / "cache" / "osv"
SETA = ROOT / "benchmarks" / "setA"
SETB = ROOT / "benchmarks" / "setB"
SETC = ROOT / "benchmarks" / "setC"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def max_rss_mb() -> float:
    value = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if sys.platform == "darwin":
        return value / (1024 * 1024)
    return value / 1024


def seta_build(item: dict) -> ProjectBuild:
    app_dir = SETA / item["app_dir"]
    return ProjectBuild(
        project_dir=app_dir,
        group_id="io.reachsbom.setA",
        artifact_id=item["id"],
        version="1.0",
        main_class=item["main_class"],
        classes_dir=app_dir / "target" / "classes",
        sbom_jars_dir=app_dir / "target" / "sbom-jars",
        runtime_jars_dir=app_dir / "target" / "runtime-jars",
    )


def prepare_app(build: ProjectBuild, tag: str) -> dict:
    started = time.perf_counter()
    sbom_path = RAW / "sbom" / f"{tag}.cdx.json"
    sbom_result = sbom.build_sbom(build, sbom_path, repo_root=ROOT)
    sbom_seconds = time.perf_counter() - started

    started = time.perf_counter()
    advisories = osv.scan_components(sbom_result.components, CACHE)
    static = reachability.load_static_advisories(ROOT / "data" / "advisories.json")
    reachability.attach_static_symbols(advisories, static)
    osv_seconds = time.perf_counter() - started

    runtime = stage2.RuntimeIndex.from_jars(build.runtime_jars(), sbom_result.components)
    return {
        "build": build,
        "tag": tag,
        "components": sbom_result.components,
        "advisories": advisories,
        "runtime": runtime,
        "sbom_seconds": sbom_seconds,
        "osv_seconds": osv_seconds,
        "edge_rules": [],
    }


def results_from_response(
    advisories,
    runtime: stage2.RuntimeIndex,
    active: dict[str, dict],
    app_dynamic: bool,
) -> list[SymbolResult]:
    results: list[SymbolResult] = []
    for advisory in advisories:
        if not advisory.symbols:
            present = runtime.component_present(advisory.purl)
            results.append(
                SymbolResult(
                    advisory_id=advisory.advisory_id,
                    class_name="",
                    method="",
                    status="ClassPresent" if present else "Present",
                    class_present=present,
                    method_present=False,
                    source="component",
                    purl=advisory.purl,
                )
            )
            continue
        for symbol in advisory.symbols:
            class_present = runtime.has_class(symbol.class_name)
            for method in symbol.methods:
                if not class_present:
                    results.append(
                        SymbolResult(
                            advisory_id=advisory.advisory_id,
                            class_name=symbol.class_name,
                            method=method,
                            status="Present",
                            class_present=False,
                            method_present=False,
                            source="stage2",
                            purl=advisory.purl,
                        )
                    )
                    continue
                entry = active.get(method)
                if entry is None:
                    results.append(
                        SymbolResult(
                            advisory_id=advisory.advisory_id,
                            class_name=symbol.class_name,
                            method=method,
                            status="ClassPresent",
                            class_present=True,
                            method_present=False,
                            source="java-missing",
                            purl=advisory.purl,
                        )
                    )
                    continue
                results.append(_method_result(advisory, symbol, method, entry, app_dynamic))
    stage2.apply_component_fallback(results, runtime)
    return results


def target_finding(findings, cve: str, component: str):
    wanted = base_purl(component)
    for finding in findings:
        if cve in finding.advisory_ids and base_purl(finding.purl) == wanted:
            return finding
    return None


def run_batch(apps: list[dict], algorithm: str, tag: str, use_edges: bool = True) -> tuple[dict, float]:
    nodes = []
    for app in apps:
        request = reachability.build_request(
            app["build"],
            app["advisories"],
            app["runtime"],
            algorithm=algorithm,
            use_edge_rules=use_edges,
            repo_root=ROOT,
        )
        node = request["apps"][0]
        if use_edges:
            for rule in app.get("edge_rules", []):
                if rule not in node["edge_rules"]:
                    node["edge_rules"].append(rule)
        nodes.append(node)
    request = {"algorithm": algorithm, "use_edge_rules": use_edges, "apps": nodes}
    started = time.perf_counter()
    response = reachability.run_analyzer(
        request,
        RAW / "analyzer" / tag,
        repo_root=ROOT,
    )
    elapsed = time.perf_counter() - started
    return response, elapsed


def app_record(app: dict, response: dict, algorithm: str, target_cve: str, target_component: str) -> dict:
    build = app["build"]
    app_id = reachability._app_id(build)
    node, _ = reachability._select_app(response, app_id)
    active = reachability.parse_analyzer_response(response, app_id)
    app_dynamic = bool(node.get("dynamic", False))
    results = results_from_response(app["advisories"], app["runtime"], active, app_dynamic)
    findings = scoring.build_findings(app["advisories"], results)
    target = target_finding(findings, target_cve, target_component)
    kept = sum(
        1
        for finding in findings
        if status_rank(finding.status) >= status_rank("PossiblyReachable")
    )
    return {
        "app": app["tag"],
        "algorithm": algorithm,
        "component_present": app["runtime"].component_present(target_component),
        "target_cve": target_cve,
        "target_status": target.status if target else "NotDetected",
        "target_risk": target.risk if target else 0.0,
        "target_path": target.path if target else [],
        "target_symbol": target.symbol if target else None,
        "findings": len(findings),
        "kept": kept,
        "dynamic": app_dynamic,
        "reachable_methods": node.get("stats", {}).get("reachable_methods", 0),
        "graph_edges": node.get("stats", {}).get("graph_edges", 0),
        "sbom_components": len(app["components"]),
        "sbom_seconds": app["sbom_seconds"],
        "osv_seconds": app["osv_seconds"],
    }


def add_expected(records: list[dict], manifest: list[dict]) -> list[dict]:
    expected = {item["id"]: item for item in manifest}
    for record in records:
        meta = expected.get(record["app"], {})
        record["library"] = meta.get("library", "")
        record["pattern"] = meta.get("pattern", "")
        record["expected"] = meta.get("expected", "")
        record["id"] = record["app"]
    return records


def write_csv(path: Path, records: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            writer.writerow(record)


def metrics(records: list[dict], positive_states: set[str]) -> dict:
    tp = fp = fn = tn = 0
    for record in records:
        expected_positive = record["expected"] in positive_states
        actual_positive = record["target_status"] in positive_states
        if expected_positive and actual_positive:
            tp += 1
        elif expected_positive and not actual_positive:
            fn += 1
        elif not expected_positive and actual_positive:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(records) if records else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def run_seta(algorithm: str, use_edges: bool = True) -> list[dict]:
    manifest = load_json(SETA / "manifest.json")
    apps = []
    for item in manifest:
        build = seta_build(item)
        app = prepare_app(build, item["id"])
        app["edge_rules"] = item.get("edge_rules", [])
        apps.append(app)
        print("[seta] prepared", item["id"], flush=True)

    grouped = {"log4j": [], "commons": [], "snakeyaml": []}
    for app in apps:
        grouped[app["tag"].split("-", 1)[0]].append(app)

    records = []
    for group_name, group_apps in grouped.items():
        print("[seta] java", group_name, algorithm, flush=True)
        response, elapsed = run_batch(
            group_apps,
            algorithm,
            f"seta-{group_name}-{algorithm}" + ("" if use_edges else "-noedges"),
            use_edges=use_edges,
        )
        print(
            "[seta] java done %s %s %.1fs" % (group_name, algorithm, elapsed),
            flush=True,
        )
        for app in group_apps:
            records.append(
                app_record(
                    app,
                    response,
                    algorithm,
                    "CVE-2021-44228"
                    if group_name == "log4j"
                    else "CVE-2022-42889"
                    if group_name == "commons"
                    else "CVE-2022-1471",
                    {
                        "log4j": "pkg:maven/org.apache.logging.log4j/log4j-core",
                        "commons": "pkg:maven/org.apache.commons/commons-text",
                        "snakeyaml": "pkg:maven/org.yaml/snakeyaml",
                    }[group_name],
                )
            )
    records = sorted(add_expected(records, manifest), key=lambda item: item["app"])
    suffix = "" if use_edges else "-noedges"
    write_json(RAW / f"seta-{algorithm}{suffix}.json", records)
    write_csv(
        TABLES / (("seta.csv" if algorithm == "rta" else "seta-cha.csv") if use_edges else "seta-noedges.csv"),
        records,
        [
            "app",
            "library",
            "pattern",
            "expected",
            "target_status",
            "target_risk",
            "component_present",
            "findings",
            "kept",
            "dynamic",
            "reachable_methods",
            "graph_edges",
            "target_path",
        ],
    )
    summary = {
        "positive_reachable_or_possible": metrics(
            records, {"Reachable", "PossiblyReachable"}
        ),
        "positive_reachable_only": metrics(records, {"Reachable"}),
        "per_pattern": {
            pattern: {
                "expected": expected,
                "correct": sum(
                    1
                    for record in records
                    if record["pattern"] == pattern
                    and record["target_status"] == expected
                ),
                "total": sum(1 for record in records if record["pattern"] == pattern),
            }
            for pattern, expected in [
                ("P1", "Present"),
                ("P2", "ClassPresent"),
                ("P3", "Reachable"),
                ("P4", "Reachable"),
                ("P5", "Reachable"),
                ("P6", "Reachable"),
                ("P7", "PossiblyReachable"),
                ("P8", "ClassPresent"),
                ("P9", "ClassPresent"),
                ("P10", "Reachable"),
            ]
        },
    }
    write_json(RAW / f"seta-{algorithm}{suffix}-metrics.json", summary)
    return records


def run_setb(algorithm: str) -> list[dict]:
    manifest = load_json(SETB / "manifest.json")
    apps = []
    for item in manifest["apps"]:
        build = maven.build_project(ROOT / item["path"], skip_build=True, repo_root=ROOT)
        app = prepare_app(build, item["name"])
        app["expected"] = item["expected_status"]
        app["id"] = item["name"]
        apps.append(app)
        print("[setb] prepared", item["name"], flush=True)

    response, elapsed = run_batch(apps, algorithm, f"setb-{algorithm}")
    print("[setb] java done %s %.1fs" % (algorithm, elapsed), flush=True)
    records = []
    for app in apps:
        record = app_record(
            app,
            response,
            algorithm,
            "CVE-2021-44228",
            "pkg:maven/org.apache.logging.log4j/log4j-core",
        )
        record["expected"] = app["expected"]
        record["id"] = app["id"]
        records.append(record)
    write_json(RAW / f"setb-{algorithm}.json", records)
    write_csv(
        TABLES / "setb.csv" if algorithm == "rta" else TABLES / "setb-cha.csv",
        records,
        [
            "app",
            "expected",
            "target_status",
            "target_risk",
            "target_path",
            "findings",
            "kept",
            "sbom_components",
        ],
    )
    return records


def run_setc(algorithm: str) -> list[dict]:
    manifest = load_json(SETC / "manifest.json")
    apps = []
    for item in manifest["projects"]:
        if item.get("build", {}).get("status") != "built":
            continue
        build = maven.build_project(
            ROOT / item["app_path"], skip_build=True, repo_root=ROOT
        )
        app = prepare_app(build, item["name"])
        app["expected"] = ""
        app["id"] = item["name"]
        apps.append(app)
        print("[setc] prepared", item["name"], flush=True)

    response, elapsed = run_batch(apps, algorithm, f"setc-{algorithm}")
    print("[setc] java done %s %.1fs" % (algorithm, elapsed), flush=True)
    records = []
    for app in apps:
        record = app_record(
            app,
            response,
            algorithm,
            "CVE-2021-44228",
            "pkg:maven/org.apache.logging.log4j/log4j-core",
        )
        record["expected"] = ""
        record["id"] = app["id"]
        record["logs"] = next(
            item["logs"] for item in manifest["projects"] if item["name"] == app["id"]
        )
        records.append(record)
    write_json(RAW / f"setc-{algorithm}.json", records)
    write_csv(
        TABLES / "setc.csv" if algorithm == "rta" else TABLES / "setc-cha.csv",
        records,
        [
            "app",
            "logs",
            "target_status",
            "target_risk",
            "target_path",
            "findings",
            "kept",
            "sbom_components",
            "sbom_seconds",
            "osv_seconds",
        ],
    )
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", dest="benchmark", choices=("a", "b", "c", "all"), required=True)
    parser.add_argument("--algorithm", choices=("rta", "cha", "both"), default="both")
    parser.add_argument(
        "--no-edge-rules",
        dest="edge_rules",
        action="store_false",
        default=True,
        help="run the Set A ablation without framework edge rules",
    )
    args = parser.parse_args()

    for directory in (RAW, TABLES, WORK, CACHE):
        directory.mkdir(parents=True, exist_ok=True)

    algorithms = ("rta", "cha") if args.algorithm == "both" else (args.algorithm,)
    if args.benchmark in ("a", "all"):
        for algorithm in algorithms:
            print("=== Set A", algorithm, flush=True)
            run_seta(algorithm, use_edges=args.edge_rules)
    if args.benchmark in ("b", "all"):
        for algorithm in algorithms:
            print("=== Set B", algorithm, flush=True)
            run_setb(algorithm)
    if args.benchmark in ("c", "all"):
        for algorithm in algorithms:
            print("=== Set C", algorithm, flush=True)
            run_setc(algorithm)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
