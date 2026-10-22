# ReachSBOM

Reachability aware vulnerability prioritization for Maven projects.

The tool generates a CycloneDX SBOM, maps components to OSV advisories,
and asks a Soot based analyzer whether the vulnerable methods are reachable
from application entry points. Findings are ranked with a stage aware score.

## Status

Work in progress. The evaluation harness and benchmark data are in this
repository as well.

## Layout

- `analyzer/reachsbom`: Python orchestrator
- `java-analyzer`: Soot based reachability analyzer
- `benchmarks/setA`: seeded benchmark applications
- `evaluation`: scripts that run the experiments
- `results`: raw output and generated tables
- `data`: symbol map and edge rules

## Quick start

    bash scripts/setup_tools.sh
    bash scripts/build_java.sh
    .venv/bin/python -m reachsbom.cli scan benchmarks/setA/log4j-p3 --out results/out
