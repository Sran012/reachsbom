from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import maven, osv, report, reachability, sbom, scoring, stage2
from .maven import BuildError, find_repo_root
from .models import ReachsbomError


LOG = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reachsbom",
        description="Reachability aware Maven SBOM scanner",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a Maven project")
    scan.add_argument("project_dir", type=Path, help="Maven project directory")
    scan.add_argument("--out", type=Path, required=True, help="output directory")
    scan.add_argument(
        "--algorithm",
        choices=("rta", "cha"),
        default="rta",
        help="call graph algorithm",
    )
    scan.add_argument(
        "--no-edge-rules",
        dest="edge_rules",
        action="store_false",
        default=True,
        help="disable framework edge rules",
    )
    scan.add_argument(
        "--skip-build",
        action="store_true",
        help="use existing target directories",
    )
    return parser


def _print_summary(
    build: maven.ProjectBuild,
    components,
    advisories,
    findings,
    out_dir: Path,
) -> None:
    print()
    print(f"Project: {build.group_id}:{build.artifact_id}:{build.version}")
    print(f"SBOM components: {len(components)}")
    print(f"Advisories: {len(advisories)}")
    print(f"Findings: {len(findings)}")

    counts = report.status_counts(findings)
    if counts:
        summary = ", ".join(
            f"{status} {counts[status]}"
            for status in ("Taint", "Reachable", "PossiblyReachable", "ClassPresent", "Present")
            if counts.get(status)
        )
        print(f"Statuses: {summary}")

    if findings:
        print()
        print("Top findings:")
        for finding in report.sorted_findings(findings)[:10]:
            print("  " + report.summary_line(finding))
    else:
        print()
        print("No advisories found.")

    print()
    print(f"Output: {out_dir}")


def run_scan(args: argparse.Namespace) -> int:
    project_dir = args.project_dir.expanduser().resolve()
    out_dir = args.out.expanduser().resolve()
    repo_root = find_repo_root(project_dir)

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReachsbomError(f"cannot create output directory {out_dir}: {exc}") from exc

    LOG.info("building %s", project_dir)
    build = maven.build_project(
        project_dir,
        skip_build=args.skip_build,
        repo_root=repo_root,
    )

    LOG.info("generating SBOM")
    sbom_result = sbom.build_sbom(
        build,
        out_dir / "sbom.cdx.json",
        repo_root=repo_root,
    )
    components = sbom_result.components

    LOG.info("querying OSV for %d components", len(components))
    cache_dir = osv.default_cache_dir(repo_root)
    advisories = osv.scan_components(components, cache_dir)

    static_advisories = reachability.load_static_advisories(
        repo_root / "data" / "advisories.json"
    )
    reachability.attach_static_symbols(advisories, static_advisories)
    osv.write_advisories(out_dir / "advisories.json", advisories)

    LOG.info("indexing runtime classpath")
    runtime_index = stage2.RuntimeIndex.from_jars(build.runtime_jars(), components)

    LOG.info("running reachability analysis")
    symbol_results = reachability.analyze(
        build,
        advisories,
        runtime_index,
        out_dir,
        algorithm=args.algorithm,
        use_edge_rules=args.edge_rules,
        edge_rules_path=repo_root / "data" / "edge_rules.json",
        repo_root=repo_root,
    )

    findings = scoring.build_findings(advisories, symbol_results)
    report.write_outputs(
        out_dir,
        findings,
        project=f"{build.group_id}:{build.artifact_id}:{build.version}",
        component_count=len(components),
        advisory_count=len(advisories),
    )

    _print_summary(build, components, advisories, findings, out_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        if args.command == "scan":
            return run_scan(args)
    except BuildError as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 1
    except ReachsbomError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"unexpected error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
