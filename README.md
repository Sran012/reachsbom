# ReachSBOM

ReachSBOM is a reachability-aware vulnerability prioritizer for Maven projects.
It generates a CycloneDX SBOM with Syft, maps components to OSV advisories,
builds a Soot call graph, and reports whether each vulnerable method can be
reached from an application entry point. Findings are ranked with a stage-aware
score that combines CVSS severity and reachability.

The repository is at <https://github.com/Sran012/reachsbom>. It contains the
tool, the seeded benchmark, the Spring Boot Log4Shell case study, five real
Spring Guides projects, the experiment scripts, and the result tables used in
the paper.

## Requirements

- JDK 17
- Maven 3.9 or newer
- Syft 1.55 or newer
- Python 3.10 or newer with `requests`
- Network access for OSV.dev queries (responses are cached)

The scripts in `scripts/env.sh` expect local tools under `.tools`. Set
`JAVA_HOME`, `PATH`, and the Python environment to your own installation if you
do not use that layout.

## Build

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
source scripts/env.sh
bash scripts/build_java.sh
```

## Scan a project

```bash
PYTHONPATH=analyzer .venv/bin/python -m reachsbom.cli scan benchmarks/setA/log4j-p3 --out results/out
```

The output directory contains `report.json`, a terminal summary, the generated
SBOM, and the analyzer request and response. Use `--algorithm cha` for the class
hierarchy analysis ablation and `--no-edge-rules` to disable framework rules.

## Results

Set A has 30 seeded applications, three libraries, and ten usage patterns.
Precision, recall, and F1 treat Reachable and Possibly reachable as positive.

| Approach | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Syft + Grype | 0.600 | 1.000 | 0.750 |
| Trivy | 0.667 | 1.000 | 0.800 |
| Direct call sites | 0.647 | 0.611 | 0.629 |
| ReachSBOM without edge rules | 1.000 | 0.833 | 0.909 |
| ReachSBOM with CHA | 1.000 | 1.000 | 1.000 |
| ReachSBOM (RTA, edge rules) | 1.000 | 1.000 | 1.000 |

On the Spring Boot case study, RTA returns Reachable for the logging
application and ClassPresent for the application that never logs request data.
CHA returns Reachable for both, which is the false positive shown in the paper.

Set C contains five Spring Guides projects. SBOM-only scanning raises 449
findings. ReachSBOM promotes four Log4Shell findings to Reachable, all of which
rank in the top four. The alert reduction rate is 99.1%. This is a filtering
rate rather than an independent false-positive estimate, because most of the
remaining advisories have no method-level symbol map.

## Reproduce the experiments

```bash
source scripts/env.sh
bash scripts/build_seta.sh

PYTHONPATH=analyzer .venv/bin/python evaluation/run_experiments.py --set a --algorithm both
PYTHONPATH=analyzer .venv/bin/python evaluation/run_experiments.py --set a --algorithm rta --no-edge-rules
PYTHONPATH=analyzer .venv/bin/python evaluation/run_experiments.py --set b --algorithm both
PYTHONPATH=analyzer .venv/bin/python evaluation/run_experiments.py --set c --algorithm rta
PYTHONPATH=analyzer .venv/bin/python evaluation/run_baselines.py
PYTHONPATH=analyzer .venv/bin/python evaluation/summarize_setc.py
.venv/bin/python evaluation/build_tables.py
```

The full call-graph runs are memory hungry. A batch of five Spring Boot apps
peaks at about 3 GB with `-Xmx3g`.

## Benchmarks

- `benchmarks/setA`: 30 small Maven applications, ground truth in
  `manifest.json`.
- `benchmarks/setB`: Spring Boot 2.5.0 applications with and without a
  request-controlled Log4j call. Download scripts for Solr and Ghidra are
  included; the two binary distributions are used for Stage 1 and Stage 2
  checks only.
- `benchmarks/setC`: five Spring Guides projects prepared with log4j-core
  2.14.1. Three add a startup Log4j call and two do not.

## Paper

The paper source and compiled PDF are in `paper/`. The experimental notes and
the exact table substitutions are recorded in `paper/PAPER_UPDATES.md`.

## License

MIT. See `LICENSE`.
