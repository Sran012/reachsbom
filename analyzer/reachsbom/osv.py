from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from .models import (
    Advisory,
    Component,
    ReachsbomError,
    base_purl,
    purl_version,
)


LOGGER = logging.getLogger(__name__)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

SEVERITY_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "MODERATE": 5.5,
    "LOW": 2.0,
    "NONE": 0.0,
}

_CVSS_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class OsvError(ReachsbomError):
    pass


def severity_score(label: str) -> float:
    return SEVERITY_SCORES.get((label or "").strip().upper(), 0.0)


def parse_cvss3_vector(vector: str) -> dict[str, str]:
    if not isinstance(vector, str) or not vector.strip():
        raise ValueError("CVSS vector is empty")

    text = vector.strip()
    pieces = text.split("/")
    if pieces[0].upper().startswith("CVSS:"):
        version = pieces[0].split(":", 1)[1]
        if not version.startswith("3."):
            raise ValueError(f"not a CVSS v3 vector: {vector}")
        pieces = pieces[1:]

    metrics: dict[str, str] = {}
    for piece in pieces:
        if not piece or ":" not in piece:
            continue
        key, value = piece.split(":", 1)
        key = key.strip().upper()
        value = value.strip().upper()
        if key in _CVSS_VALUES:
            if value not in _CVSS_VALUES[key]:
                raise ValueError(f"invalid {key} value {value} in {vector}")
            metrics[key] = value
        elif key == "S":
            if value not in ("U", "C"):
                raise ValueError(f"invalid scope value {value} in {vector}")
            metrics[key] = value
        elif key == "PR":
            if value not in _PR_UNCHANGED:
                raise ValueError(f"invalid PR value {value} in {vector}")
            metrics[key] = value

    missing = [key for key in _REQUIRED_METRICS if key not in metrics]
    if missing:
        raise ValueError(f"missing CVSS metrics {', '.join(missing)} in {vector}")
    return metrics


def _round_up(value: float) -> float:
    return math.ceil(round(value * 10, 6)) / 10.0


def cvss3_base_score(vector: str) -> float:
    metrics = parse_cvss3_vector(vector)
    scope_changed = metrics["S"] == "C"

    confidentiality = _CVSS_VALUES["C"][metrics["C"]]
    integrity = _CVSS_VALUES["I"][metrics["I"]]
    availability = _CVSS_VALUES["A"][metrics["A"]]
    iss = 1.0 - (
        (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability)
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    privilege = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
    exploitability = (
        8.22
        * _CVSS_VALUES["AV"][metrics["AV"]]
        * _CVSS_VALUES["AC"][metrics["AC"]]
        * privilege
        * _CVSS_VALUES["UI"][metrics["UI"]]
    )

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)
    return _round_up(score)


def _severity_label(record: dict) -> str:
    for container in ("database_specific", "ecosystem_specific"):
        specific = record.get(container)
        if isinstance(specific, dict):
            label = specific.get("severity")
            if isinstance(label, str) and label.strip():
                return label.strip().upper()
    return ""


def _v3_vector(record: dict) -> str:
    severity = record.get("severity")
    if isinstance(severity, str) and "CVSS:3" in severity.upper():
        return severity
    if isinstance(severity, list):
        for item in severity:
            if isinstance(item, str):
                if "CVSS:3" in item.upper():
                    return item
                continue
            if not isinstance(item, dict):
                continue
            score = item.get("score")
            if not isinstance(score, str) or not score.strip():
                continue
            item_type = str(item.get("type") or "").upper()
            if "CVSS:3" in score.upper():
                return score
            if item_type in ("CVSS_V3", "CVSS_V30", "CVSS_V31"):
                return f"CVSS:3.1/{score.strip()}"
    return ""


def _score_and_severity(record: dict) -> tuple[float, str]:
    vector = _v3_vector(record)
    label = _severity_label(record)
    if vector:
        try:
            score = cvss3_base_score(vector)
        except ValueError:
            score = 0.0
        else:
            if not label:
                if score >= 9.0:
                    label = "CRITICAL"
                elif score >= 7.0:
                    label = "HIGH"
                elif score >= 4.0:
                    label = "MEDIUM"
                elif score > 0.0:
                    label = "LOW"
            return score, label
    return severity_score(label), label


def _version_key(version: str) -> tuple:
    tokens = re.findall(r"[0-9]+|[A-Za-z]+", version.lower())
    key: list[tuple[int, int]] = []
    for token in tokens:
        if token.isdigit():
            key.append((1, int(token)))
        else:
            key.append((0, 0))
    while key and key[-1] == (1, 0):
        key.pop()
    key.append((2, 0))
    return tuple(key)


def compare_versions(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _affected_matches(package: dict, purl: str) -> bool:
    affected_purl = str(package.get("purl") or "")
    if affected_purl and base_purl(affected_purl) == base_purl(purl):
        return True
    if package.get("ecosystem") != "Maven":
        return False
    name = str(package.get("name") or "")
    if ":" not in name:
        return False
    expected = base_purl(purl)
    if expected.startswith("pkg:maven/"):
        expected = expected[len("pkg:maven/"):]
    return name == expected


def extract_fixed_version(record: dict, purl: str) -> str:
    fixed: list[str] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict) or not _affected_matches(package, purl):
            continue
        for version_range in affected.get("ranges") or []:
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.append(str(event["fixed"]))

    fixed = sorted(set(fixed), key=_version_key)
    if not fixed:
        return ""
    installed = purl_version(purl)
    if installed:
        newer = [item for item in fixed if compare_versions(item, installed) > 0]
        if newer:
            fixed = newer
    return fixed[0]


def _record_ids(record: dict) -> set[str]:
    result = set()
    record_id = record.get("id")
    if isinstance(record_id, str) and record_id:
        result.add(record_id)
    for alias in record.get("aliases") or []:
        if isinstance(alias, str) and alias:
            result.add(alias)
    return result


def _merge_group(records: list[dict]) -> dict:
    ids: set[str] = set()
    for record in records:
        ids.update(_record_ids(record))

    cve_ids = sorted(item for item in ids if item.startswith("CVE-"))
    canonical = cve_ids[0] if cve_ids else sorted(ids)[0]

    merged = dict(records[0])
    merged["id"] = canonical
    merged["aliases"] = sorted(ids - {canonical})

    summary = next(
        (str(record.get("summary")) for record in records if record.get("summary")),
        "",
    )
    if summary:
        merged["summary"] = summary
    details = next(
        (str(record.get("details")) for record in records if record.get("details")),
        "",
    )
    if details:
        merged["details"] = details

    severity = []
    seen_severity = set()
    for record in records:
        value = record.get("severity")
        items = value if isinstance(value, list) else [value] if value else []
        for item in items:
            key = json.dumps(item, sort_keys=True)
            if key not in seen_severity:
                seen_severity.add(key)
                severity.append(item)
    if severity:
        merged["severity"] = severity

    database_specific: dict[str, Any] = {}
    for record in records:
        value = record.get("database_specific")
        if isinstance(value, dict):
            for key, item in value.items():
                database_specific.setdefault(key, item)
    if database_specific:
        merged["database_specific"] = database_specific

    affected = []
    seen_affected = set()
    for record in records:
        for item in record.get("affected") or []:
            key = json.dumps(item, sort_keys=True)
            if key not in seen_affected:
                seen_affected.add(key)
                affected.append(item)
    if affected:
        merged["affected"] = affected

    references = []
    seen_references = set()
    for record in records:
        for item in record.get("references") or []:
            key = json.dumps(item, sort_keys=True)
            if key not in seen_references:
                seen_references.add(key)
                references.append(item)
    if references:
        merged["references"] = references

    return merged


def merge_records(records: list[dict]) -> list[dict]:
    groups: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        ids = _record_ids(record)
        if not ids:
            continue
        matches = [group for group in groups if ids & group["ids"]]
        if not matches:
            groups.append({"ids": set(ids), "records": [record]})
            continue
        first = matches[0]
        first["ids"].update(ids)
        first["records"].append(record)
        for extra in matches[1:]:
            first["ids"].update(extra["ids"])
            first["records"].extend(extra["records"])
            groups.remove(extra)
    return [_merge_group(group["records"]) for group in groups]


def advisory_from_record(record: dict, component: Component) -> Advisory:
    cvss, severity = _score_and_severity(record)
    canonical = str(record.get("id") or "")
    aliases = [
        str(item)
        for item in record.get("aliases") or []
        if isinstance(item, str) and item != canonical
    ]
    return Advisory(
        advisory_id=canonical,
        purl=component.purl,
        component=component.name,
        cvss=cvss,
        fixed_version=extract_fixed_version(record, component.purl),
        summary=str(record.get("summary") or ""),
        aliases=aliases,
        severity=severity,
        source="OSV",
    )


def advisories_from_response(response: dict, component: Component) -> list[Advisory]:
    if not isinstance(response, dict):
        return []
    records = merge_records(response.get("vulns") or [])
    advisories = [advisory_from_record(record, component) for record in records]
    return [advisory for advisory in advisories if advisory.advisory_id]


def cache_key(purl: str) -> str:
    return hashlib.sha256(purl.encode("utf-8")).hexdigest()


def default_cache_dir(repo_root: Path) -> Path:
    return repo_root / "results" / "cache" / "osv"


def query_osv(
    purl: str,
    cache_dir: Path,
    session: requests.Session | None = None,
    timeout: float = 30.0,
    refresh: bool = False,
    url: str = OSV_QUERY_URL,
) -> dict:
    if not purl:
        return {"vulns": []}
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{cache_key(purl)}.json"

    if cache_path.is_file() and not refresh:
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(cached, dict):
                return cached
        except (OSError, json.JSONDecodeError):
            LOGGER.warning("ignoring unreadable OSV cache file %s", cache_path)

    payload = {"package": {"purl": purl}}
    headers = {"User-Agent": "reachsbom/0.1"}
    try:
        if session is not None:
            response = session.post(url, json=payload, headers=headers, timeout=timeout)
        else:
            response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise OsvError(f"OSV query failed for {purl}: {exc}") from exc
    if not isinstance(data, dict):
        raise OsvError(f"OSV returned an unexpected response for {purl}")

    try:
        cache_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        LOGGER.warning("could not write OSV cache %s: %s", cache_path, exc)
    return data


def scan_components(
    components: list[Component],
    cache_dir: Path,
    timeout: float = 30.0,
    workers: int = 6,
) -> list[Advisory]:
    unique: dict[str, Component] = {}
    for component in components:
        if component.purl and component.purl not in unique:
            unique[component.purl] = component

    def load(component: Component) -> list[Advisory]:
        response = query_osv(component.purl, cache_dir, timeout=timeout)
        return advisories_from_response(response, component)

    results: list[Advisory] = []
    if workers <= 1 or len(unique) <= 1:
        for component in unique.values():
            try:
                results.extend(load(component))
            except OsvError as exc:
                LOGGER.warning("%s", exc)
        return results

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(load, component): component for component in unique.values()
        }
        for future in as_completed(futures):
            component = futures[future]
            try:
                results.extend(future.result())
            except OsvError as exc:
                LOGGER.warning("%s", exc)
            except Exception as exc:
                LOGGER.warning("OSV lookup failed for %s: %s", component.purl, exc)

    results.sort(key=lambda item: (item.base_purl, item.advisory_id))
    return results


def write_advisories(path: Path, advisories: list[Advisory]) -> None:
    records: dict[str, dict] = {}
    for advisory in sorted(advisories, key=lambda item: (item.base_purl, item.advisory_id)):
        key = advisory.advisory_id
        if key in records:
            key = f"{key}@{advisory.base_purl}"
        records[key] = advisory.to_dict()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
