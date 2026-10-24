# Paper updates

The file `paper/reachsbom.tex` is a copy of the original submission source. The
original in `Downloads` was not modified. The paper now reports the results of
the repository runs from 2026-10-25.

## Environment

- Temurin JDK 17
- Maven 3.9.9
- Soot 4.7.1
- Syft 1.55.0
- Grype 0.121.0
- Trivy 0.76.1
- OSV.dev advisory data queried on 2026-10-25

## Table changes

### Table IV, Set A

The six rows now contain measured precision, recall, and F1:

| Approach | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Syft + Grype | 0.600 | 1.000 | 0.750 |
| Trivy | 0.667 | 1.000 | 0.800 |
| Direct call sites | 0.647 | 0.611 | 0.629 |
| No edge rules | 1.000 | 0.833 | 0.909 |
| CHA | 1.000 | 1.000 | 1.000 |
| RTA + edge rules | 1.000 | 1.000 | 1.000 |

Raw data: `results/tables/seta_metrics.csv`, `results/tables/baselines.csv`,
and `results/raw/seta-*-metrics.json`.

### Table V, Set B

Solr and Ghidra are marked `Stage 2` because the current prototype needs a
Maven build for the call graph. The Spring Boot row is `Reachable` under both
RTA and CHA. The text now reports the ablation result: on `spring-nolog`, RTA
returns ClassPresent and CHA returns Reachable.

### Table VI, Set C

The corpus is five Spring Guides projects, not 15. Measured values:

- SBOM-only findings: 449
- Findings kept as reachable: 4
- Alert reduction rate: 99.1 percent
- Precision at 10: 0.40
- Reviewer agreement: single reviewer, not measured

The table now says "alert reduction rate" instead of "false-positive reduction
rate". The 99.1 percent figure counts every advisory that was not promoted to a
reachable method. Most of those advisories have no method-level symbol map, so
this is a filtering rate, not an independent false-positive estimate. This is
stated in the results text.

### Table VII, overhead

- SBOM generation: 2.25 s, 194 MB
- Advisory mapping: 1.21 s, 29 MB
- Call graph and reachability: 20.6 s per project, 3059 MB batch peak
- Scoring and report: 0.06 s, 16 MB

The call graph was run as one batch over five projects. The time is amortized
over the batch and the memory is the batch peak.

## Text changes

- Set C changed from 15 projects with two reviewers and Cohen's kappa to five
  projects with one reviewer. The single-reviewer protocol is stated in the
  evaluation design, the results, and the limitations.
- The CodeQL baseline was replaced with a direct call-site query over compiled
  classes. This is the baseline that was actually run.
- Set B now states that Solr and Ghidra are used for Stage 1 and Stage 2 only.
- The conclusion says "five real Maven projects" instead of "a set of real
  projects".
- The FPRR equation was replaced with a notation that uses `N_kept` and
  `N_raised`, because the original expression overflowed the column.

## Review notes

The reviewer labels for the Set C top 10 are in
`results/tables/setc-review.csv`. A finding is marked "confirmed reachable"
only when the tool returned a path from an application entry point to the
vulnerable method. The other six top-10 findings are component-level
advisories without a symbol map. Four confirmed reachable findings out of ten
gives precision at 10 equal to 0.40.

The paper should not claim two-reviewer agreement or Cohen's kappa. The current
text does not.
