from __future__ import annotations

import logging
import re
import zipfile
from collections import defaultdict
from pathlib import Path

from .models import (
    Component,
    SymbolResult,
    base_purl,
    maven_purl,
    status_rank,
)


LOGGER = logging.getLogger(__name__)


def _parse_properties(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        split_at = min(
            [index for index in (line.find("="), line.find(":")) if index != -1],
            default=-1,
        )
        if split_at == -1:
            continue
        key = line[:split_at].strip()
        value = line[split_at + 1:].strip()
        if key:
            result[key] = value
    return result


def class_from_signature(signature: str) -> str:
    value = signature.strip()
    if value.startswith("<"):
        body = value[1:]
        colon = body.find(":")
        if colon > 0:
            return body[:colon]
    return ""


class RuntimeIndex:
    def __init__(self, jars, components: list[Component] | None = None):
        self.jars = sorted({Path(item).expanduser().resolve() for item in jars})
        self.components = list(components or [])
        self.class_jars: dict[str, list[Path]] = defaultdict(list)
        self.jar_components: dict[Path, str] = {}
        self.component_jars: dict[str, set[Path]] = defaultdict(set)
        self._build()

    @classmethod
    def from_jars(cls, jars, components: list[Component] | None = None) -> "RuntimeIndex":
        return cls(jars, components)

    def _component_for_jar(self, jar: Path, pom_purl: str) -> str:
        if pom_purl:
            return pom_purl
        for component in self.components:
            if jar.stem == f"{component.name}-{component.version}":
                return component.purl
        return ""

    def _read_pom_properties(self, archive: zipfile.ZipFile) -> str:
        pattern = re.compile(r"^META-INF/maven/[^/]+/[^/]+/pom\.properties$")
        for name in archive.namelist():
            if not pattern.match(name):
                continue
            try:
                text = archive.read(name).decode("utf-8", "replace")
            except (KeyError, OSError):
                continue
            values = _parse_properties(text)
            group = values.get("groupId", "")
            artifact = values.get("artifactId", "")
            version = values.get("version", "")
            if group and artifact and version:
                return maven_purl(group, artifact, version)
        return ""

    def _index_jar(self, jar: Path) -> None:
        try:
            archive = zipfile.ZipFile(jar)
        except (OSError, zipfile.BadZipFile) as exc:
            LOGGER.warning("cannot read runtime jar %s: %s", jar, exc)
            return

        with archive:
            component = self._component_for_jar(jar, self._read_pom_properties(archive))
            if component:
                self.jar_components[jar] = component
                self.component_jars[base_purl(component)].add(jar)

            for entry in archive.namelist():
                name = entry
                if name.startswith("META-INF/versions/"):
                    pieces = name.split("/")
                    if len(pieces) > 3:
                        name = "/".join(pieces[3:])
                if not name.endswith(".class") or name.startswith("META-INF/"):
                    continue
                if name in ("module-info.class", "package-info.class"):
                    continue
                class_name = name[:-len(".class")].replace("/", ".")
                if not class_name:
                    continue
                if jar not in self.class_jars[class_name]:
                    self.class_jars[class_name].append(jar)

    def _build(self) -> None:
        for jar in self.jars:
            self._index_jar(jar)

    def has_class(self, class_name: str) -> bool:
        return class_name in self.class_jars

    def jars_for_class(self, class_name: str) -> list[Path]:
        return list(self.class_jars.get(class_name, []))

    def component_for_jar(self, jar: Path) -> str:
        return self.jar_components.get(Path(jar).resolve(), "")

    def component_for_class(self, class_name: str) -> str:
        for jar in self.class_jars.get(class_name, []):
            component = self.component_for_jar(jar)
            if component:
                return component
        return ""

    def component_present(self, component_purl: str) -> bool:
        return base_purl(component_purl) in self.component_jars

    def classes_for_component(self, component_purl: str) -> set[str]:
        base = base_purl(component_purl)
        jars = self.component_jars.get(base, set())
        return {
            class_name
            for class_name, class_jars in self.class_jars.items()
            if any(jar in jars for jar in class_jars)
        }


def _reachable_classes(results: list[SymbolResult]) -> set[str]:
    classes = set()
    for result in results:
        if status_rank(result.status) < status_rank("Reachable"):
            continue
        for item in result.path:
            class_name = class_from_signature(item)
            if class_name:
                classes.add(class_name)
        if result.class_name:
            classes.add(result.class_name)
    return classes


def apply_component_fallback(
    results: list[SymbolResult],
    index: RuntimeIndex,
) -> list[SymbolResult]:
    reachable = _reachable_classes(results)
    if not reachable:
        return results

    reachable_components = set()
    for class_name in reachable:
        component = index.component_for_class(class_name)
        if component:
            reachable_components.add(base_purl(component))
    if not reachable_components:
        return results

    for result in results:
        if not result.class_present:
            continue
        if status_rank(result.status) >= status_rank("PossiblyReachable"):
            continue
        component = index.component_for_class(result.class_name)
        if component and base_purl(component) in reachable_components:
            result.status = "PossiblyReachable"
            result.fallback = True
    return results
