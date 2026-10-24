from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import Finding, STATUS_ORDER


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            -item.risk,
            item.component.lower(),
            item.advisory_ids[0] if item.advisory_ids else "",
        ),
    )


def write_findings(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [finding.to_dict() for finding in sorted_findings(findings)]
    path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


def status_counts(findings: list[Finding]) -> Counter:
    return Counter(finding.status for finding in findings)


def summary_line(finding: Finding) -> str:
    advisory_id = finding.advisory_ids[0] if finding.advisory_ids else "unknown"
    component = finding.component
    if finding.fixed_version:
        fixed = f"fixed {finding.fixed_version}"
    else:
        fixed = "fixed unknown"
    return (
        f"{finding.risk:5.2f}  {finding.status:<17}  {advisory_id:<16}  "
        f"{component:<30}  {fixed}"
    )


def render_report(
    findings: list[Finding],
    project: str = "",
    component_count: int = 0,
    advisory_count: int = 0,
) -> str:
    findings = sorted_findings(findings)
    lines = ["ReachSBOM report", ""]
    if project:
        lines.append(f"Project: {project}")
    lines.append(f"SBOM components: {component_count}")
    lines.append(f"Advisories: {advisory_count}")
    lines.append(f"Findings: {len(findings)}")
    lines.append("")

    counts = status_counts(findings)
    lines.append("Status summary:")
    for status in reversed(STATUS_ORDER):
        if counts.get(status):
            lines.append(f"  {status}: {counts[status]}")
    if not counts:
        lines.append("  none")
    lines.append("")

    if not findings:
        lines.append("No advisories found.")
        return "\n".join(lines) + "\n"

    lines.append("Findings (highest risk first):")
    for number, finding in enumerate(findings, start=1):
        ids = ", ".join(finding.advisory_ids) or "unknown"
        lines.append("")
        lines.append(f"{number}. {finding.component}  {finding.purl}")
        lines.append(f"   advisories: {ids}")
        lines.append(
            f"   cvss: {finding.cvss:.1f}  fixed: "
            f"{finding.fixed_version or 'unknown'}"
        )
        lines.append(f"   status: {finding.status}  risk: {finding.risk:.3f}")
        lines.append(f"   symbol: {finding.symbol or '(component level)'}")
        if finding.path:
            lines.append("   path:")
            for item in finding.path:
                lines.append(f"     {item}")
        else:
            lines.append("   path: not available")
    return "\n".join(lines) + "\n"


def write_outputs(
    out_dir: Path,
    findings: list[Finding],
    project: str = "",
    component_count: int = 0,
    advisory_count: int = 0,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.json"
    report_path = out_dir / "report.txt"
    write_findings(findings_path, findings)
    report_path.write_text(
        render_report(findings, project, component_count, advisory_count),
        encoding="utf-8",
    )
    return findings_path, report_path
