from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


STATUS_ORDER = (
    "Present",
    "ClassPresent",
    "PossiblyReachable",
    "Reachable",
    "Taint",
)
STATUS_RANK = {name: index for index, name in enumerate(STATUS_ORDER)}


class ReachsbomError(Exception):
    """Base error for expected orchestrator failures."""


def status_rank(status: str) -> int:
    return STATUS_RANK.get(status, -1)


def strongest_status(statuses, default: str = "Present") -> str:
    best = default
    best_rank = status_rank(default)
    for status in statuses:
        rank = status_rank(status)
        if rank > best_rank:
            best = status
            best_rank = rank
    return best


def base_purl(purl: str) -> str:
    if not purl:
        return ""
    value = purl.split("?", 1)[0].split("#", 1)[0]
    at = value.rfind("@")
    slash = value.rfind("/")
    if at > slash:
        value = value[:at]
    return value


def purl_version(purl: str) -> str:
    if not purl:
        return ""
    value = purl.split("?", 1)[0].split("#", 1)[0]
    at = value.rfind("@")
    slash = value.rfind("/")
    if at > slash:
        return value[at + 1:]
    return ""


def purl_name(purl: str) -> str:
    value = base_purl(purl)
    if not value:
        return ""
    return value.rsplit("/", 1)[-1]


def purl_namespace(purl: str) -> str:
    value = base_purl(purl)
    if value.startswith("pkg:"):
        value = value[4:]
    parts = value.split("/")
    if len(parts) < 3:
        return ""
    return "/".join(parts[1:-1])


def maven_purl(group_id: str, artifact_id: str, version: str = "") -> str:
    purl = f"pkg:maven/{group_id}/{artifact_id}"
    if version:
        purl += f"@{version}"
    return purl


def add_purl_version(purl: str, version: str) -> str:
    if not purl or not version or purl_version(purl):
        return purl
    base, _, fragment = purl.partition("#")
    base, _, query = base.partition("?")
    result = f"{base}@{version}"
    if query:
        result += f"?{query}"
    if fragment:
        result += f"#{fragment}"
    return result


@dataclass(frozen=True)
class Component:
    name: str
    version: str = ""
    purl: str = ""
    group: str = ""
    scope: str = ""

    @property
    def base_purl(self) -> str:
        return base_purl(self.purl)

    def display_name(self) -> str:
        if self.version:
            return f"{self.name}-{self.version}"
        return self.name


@dataclass
class ProjectBuild:
    project_dir: Path
    group_id: str
    artifact_id: str
    version: str
    main_class: str
    classes_dir: Path
    sbom_jars_dir: Path
    runtime_jars_dir: Path
    main_classes: list[str] = field(default_factory=list)

    @property
    def purl(self) -> str:
        return maven_purl(self.group_id, self.artifact_id, self.version)

    def runtime_jars(self) -> list[Path]:
        if not self.runtime_jars_dir.is_dir():
            return []
        return sorted(self.runtime_jars_dir.glob("*.jar"))

    def sbom_jars(self) -> list[Path]:
        if not self.sbom_jars_dir.is_dir():
            return []
        return sorted(self.sbom_jars_dir.glob("*.jar"))

    def component(self) -> Component:
        return Component(
            name=self.artifact_id,
            version=self.version,
            purl=self.purl,
            group=self.group_id,
        )


@dataclass(frozen=True)
class SymbolRef:
    advisory_id: str
    class_name: str
    methods: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"class": self.class_name, "methods": list(self.methods)}


@dataclass
class Advisory:
    advisory_id: str
    purl: str
    component: str = ""
    cvss: float = 0.0
    fixed_version: str = ""
    summary: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: str = ""
    symbols: list[SymbolRef] = field(default_factory=list)
    source: str = "OSV"

    @property
    def base_purl(self) -> str:
        return base_purl(self.purl)

    def all_ids(self) -> list[str]:
        result = [self.advisory_id]
        for alias in self.aliases:
            if alias and alias not in result:
                result.append(alias)
        return result

    def to_dict(self) -> dict[str, Any]:
        ghsa = next((item for item in self.aliases if item.startswith("GHSA-")), "")
        return {
            "id": self.advisory_id,
            "ghsa": ghsa,
            "component": self.purl,
            "name": self.component,
            "cvss": self.cvss,
            "fixed": self.fixed_version,
            "summary": self.summary,
            "aliases": list(self.aliases),
            "severity": self.severity,
            "symbols": [symbol.to_dict() for symbol in self.symbols],
            "source": self.source,
        }


@dataclass
class SymbolResult:
    advisory_id: str
    class_name: str
    method: str = ""
    status: str = "Present"
    path: list[str] = field(default_factory=list)
    dynamic: bool = False
    class_present: bool = True
    method_present: bool = False
    fallback: bool = False
    source: str = "stage2"
    purl: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "class": self.class_name,
            "method": self.method,
            "status": self.status,
            "path": list(self.path),
            "dynamic": self.dynamic,
            "class_present": self.class_present,
            "method_present": self.method_present,
            "fallback": self.fallback,
            "source": self.source,
            "purl": self.purl,
        }


@dataclass
class Finding:
    component: str
    purl: str
    advisory_ids: list[str]
    cvss: float
    fixed_version: str
    status: str
    path: list[str]
    risk: float
    symbol: str | None
    advisory_id: str = ""
    severity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "purl": self.purl,
            "advisory_ids": list(self.advisory_ids),
            "cvss": round(self.cvss, 1),
            "fixed_version": self.fixed_version,
            "status": self.status,
            "path": list(self.path),
            "risk": self.risk,
            "symbol": self.symbol,
        }
