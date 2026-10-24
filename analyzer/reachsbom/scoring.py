from __future__ import annotations

from .models import (
    Advisory,
    Finding,
    SymbolResult,
    status_rank,
)


WEIGHTS = {
    "Present": 0.2,
    "ClassPresent": 0.4,
    "PossiblyReachable": 0.6,
    "Reachable": 0.8,
    "Taint": 1.0,
}


def weight_for(status: str) -> float:
    return WEIGHTS.get(status, 0.0)


def risk_score(cvss: float, status: str) -> float:
    score = max(0.0, min(float(cvss or 0.0), 10.0))
    return round(score / 10.0 * weight_for(status), 4)


def select_result(results: list[SymbolResult]) -> SymbolResult | None:
    if not results:
        return None
    return max(
        results,
        key=lambda item: (
            status_rank(item.status),
            len(item.path),
            bool(item.fallback),
            item.method,
        ),
    )


def build_finding(advisory: Advisory, results: list[SymbolResult]) -> Finding:
    best = select_result(results)
    status = best.status if best else "Present"
    path = list(best.path) if best else []
    symbol = best.method if best and best.method else None
    if symbol is None and advisory.symbols and advisory.symbols[0].methods:
        symbol = advisory.symbols[0].methods[0]

    return Finding(
        component=advisory.component or advisory.purl,
        purl=advisory.purl,
        advisory_ids=advisory.all_ids(),
        cvss=advisory.cvss,
        fixed_version=advisory.fixed_version,
        status=status,
        path=path,
        risk=risk_score(advisory.cvss, status),
        symbol=symbol,
        advisory_id=advisory.advisory_id,
        severity=advisory.severity,
    )


def build_findings(
    advisories: list[Advisory],
    results: list[SymbolResult],
) -> list[Finding]:
    findings = []
    for advisory in advisories:
        matches = [
            result
            for result in results
            if result.advisory_id == advisory.advisory_id
            and (not result.purl or result.purl == advisory.purl)
        ]
        findings.append(build_finding(advisory, matches))

    findings.sort(
        key=lambda item: (
            -item.risk,
            item.component.lower(),
            item.advisory_ids[0] if item.advisory_ids else "",
        )
    )
    return findings
