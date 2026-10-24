from __future__ import annotations

import logging
import os
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .models import ProjectBuild, ReachsbomError


LOGGER = logging.getLogger(__name__)


class BuildError(ReachsbomError):
    pass


@dataclass(frozen=True)
class PomInfo:
    group_id: str
    artifact_id: str
    version: str
    packaging: str = "jar"


@dataclass(frozen=True)
class Toolchain:
    repo_root: Path
    java_home: Path
    maven: Path
    java: Path
    syft: Path


def find_repo_root(start: Path | None = None) -> Path:
    configured = os.environ.get("REACHSBOM_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()

    search = []
    if start is not None:
        search.append(Path(start).resolve())
    search.append(Path.cwd().resolve())
    search.append(Path(__file__).resolve().parent)

    for candidate in search:
        for parent in (candidate, *candidate.parents):
            if (parent / "data" / "advisories.json").is_file():
                return parent
            if (parent / ".tools").is_dir() and (parent / "analyzer").is_dir():
                return parent

    return Path(__file__).resolve().parents[2]


def toolchain(repo_root: Path | None = None) -> Toolchain:
    root = (repo_root or find_repo_root()).resolve()
    java_home = Path(os.environ.get("REACHSBOM_JAVA_HOME", root / ".tools" / "jdk17"))
    maven = Path(os.environ.get("REACHSBOM_MVN", root / ".tools" / "maven" / "bin" / "mvn"))
    syft = Path(os.environ.get("REACHSBOM_SYFT", root / ".tools" / "bin" / "syft"))
    return Toolchain(
        repo_root=root,
        java_home=java_home,
        maven=maven,
        java=java_home / "bin" / "java",
        syft=syft,
    )


def build_env(repo_root: Path | None = None) -> dict[str, str]:
    tools = toolchain(repo_root)
    env = os.environ.copy()
    env["JAVA_HOME"] = str(tools.java_home)
    prepend = [
        str(tools.maven.parent),
        str(tools.java_home / "bin"),
        str(tools.syft.parent),
    ]
    current = env.get("PATH", "")
    env["PATH"] = os.pathsep.join(prepend + ([current] if current else []))
    return env


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _child_text(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    child = _first_child(element, name)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _properties(project: ET.Element) -> dict[str, str]:
    node = _first_child(project, "properties")
    if node is None:
        return {}
    result = {}
    for child in node:
        if child.text is not None:
            result[_local_name(child.tag)] = child.text.strip()
    return result


def _resolve(value: str, variables: dict[str, str]) -> str:
    result = value
    for _ in range(10):
        start = result.find("${")
        if start == -1:
            break
        end = result.find("}", start + 2)
        if end == -1:
            break
        key = result[start + 2:end]
        replacement = variables.get(key)
        if replacement is None:
            break
        result = result[:start] + replacement + result[end + 1:]
    return result


def parse_pom(pom_path: Path) -> PomInfo:
    if not pom_path.is_file():
        raise BuildError(f"pom.xml not found at {pom_path}")
    try:
        project = ET.parse(pom_path).getroot()
    except ET.ParseError as exc:
        raise BuildError(f"cannot parse {pom_path}: {exc}") from exc

    parent = _first_child(project, "parent")
    group_id = _child_text(project, "groupId") or _child_text(parent, "groupId")
    artifact_id = _child_text(project, "artifactId")
    version = _child_text(project, "version") or _child_text(parent, "version")
    packaging = _child_text(project, "packaging") or "jar"

    variables = _properties(project)
    variables.update(
        {
            "project.groupId": group_id,
            "pom.groupId": group_id,
            "project.artifactId": artifact_id,
            "pom.artifactId": artifact_id,
            "project.version": version,
            "pom.version": version,
            "project.parent.groupId": _child_text(parent, "groupId"),
            "project.parent.artifactId": _child_text(parent, "artifactId"),
            "project.parent.version": _child_text(parent, "version"),
        }
    )
    for key, value in list(variables.items()):
        variables[key] = _resolve(value, variables)

    group_id = _resolve(group_id, variables)
    artifact_id = _resolve(artifact_id, variables)
    version = _resolve(version, variables)

    if not group_id or not artifact_id or not version:
        raise BuildError(f"pom.xml is missing groupId, artifactId, or version: {pom_path}")
    return PomInfo(group_id, artifact_id, version, packaging)


def _u2(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def _u4(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def _skip_member(data: bytes, offset: int) -> int:
    offset += 6
    attribute_count = _u2(data, offset)
    offset += 2
    for _ in range(attribute_count):
        offset += 2
        length = _u4(data, offset)
        offset += 4 + length
    return offset


def _class_info(path: Path) -> tuple[str, list[tuple[int, str, str]]] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None

    try:
        constant_count = _u2(data, 8)
        offset = 10
        utf8: dict[int, str] = {}
        class_names: dict[int, int] = {}
        index = 1
        while index < constant_count:
            tag = data[offset]
            offset += 1
            if tag == 1:
                length = _u2(data, offset)
                offset += 2
                utf8[index] = data[offset:offset + length].decode("utf-8", "replace")
                offset += length
            elif tag in (7, 8, 16, 19, 20):
                value = _u2(data, offset)
                offset += 2
                if tag == 7:
                    class_names[index] = value
            elif tag == 15:
                offset += 3
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                offset += 4
            elif tag in (5, 6):
                offset += 8
                index += 1
            else:
                return None
            index += 1

        this_class = _u2(data, offset + 2)
        offset += 6
        interfaces = _u2(data, offset)
        offset += 2 + 2 * interfaces
        field_count = _u2(data, offset)
        offset += 2
        for _ in range(field_count):
            offset = _skip_member(data, offset)

        method_count = _u2(data, offset)
        offset += 2
        methods = []
        for _ in range(method_count):
            access = _u2(data, offset)
            name = utf8.get(_u2(data, offset + 2), "")
            descriptor = utf8.get(_u2(data, offset + 4), "")
            methods.append((access, name, descriptor))
            offset = _skip_member(data, offset)

        class_name = utf8.get(class_names.get(this_class, -1), "")
        if not class_name:
            return None
        return class_name.replace("/", "."), methods
    except (IndexError, struct.error):
        return None


def find_main_classes(classes_dir: Path) -> list[str]:
    if not classes_dir.is_dir():
        return []
    found = set()
    for path in sorted(classes_dir.rglob("*.class")):
        info = _class_info(path)
        if info is None:
            continue
        class_name, methods = info
        for access, name, descriptor in methods:
            if name != "main" or descriptor != "([Ljava/lang/String;)V":
                continue
            is_public_static = bool(access & 0x0001) and bool(access & 0x0008)
            if is_public_static:
                found.add(class_name)
                break
    return sorted(found)


def choose_main_class(candidates: list[str], artifact_id: str) -> str:
    if not candidates:
        raise BuildError(
            "no public static void main(String[]) found under target/classes"
        )
    if len(candidates) == 1:
        return candidates[0]

    artifact_key = "".join(ch for ch in artifact_id.lower() if ch.isalnum())

    def score(name: str) -> tuple:
        simple = name.rsplit(".", 1)[-1].lower()
        normalized = "".join(ch for ch in simple if ch.isalnum())
        hints = 0
        if normalized.endswith("application"):
            hints -= 3
        if normalized in ("main", "app"):
            hints -= 2
        if artifact_key and artifact_key in normalized:
            hints -= 2
        return (hints, "$" in name, name.count("."), name)

    chosen = sorted(candidates, key=score)[0]
    LOGGER.warning(
        "multiple main classes found, using %s (candidates: %s)",
        chosen,
        ", ".join(candidates),
    )
    return chosen


def _run(command: list[str], project_dir: Path, env: dict[str, str]) -> None:
    try:
        completed = subprocess.run(
            command,
            cwd=project_dir,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BuildError(f"command not found: {command[0]}") from exc

    if completed.returncode != 0:
        output = (completed.stderr or completed.stdout or "").strip()
        tail = "\n".join(output.splitlines()[-20:])
        raise BuildError(
            f"Maven command failed with exit code {completed.returncode}: "
            f"{' '.join(command)}\n{tail}"
        )


def build_project(
    project_dir: Path,
    skip_build: bool = False,
    repo_root: Path | None = None,
) -> ProjectBuild:
    project_dir = project_dir.expanduser().resolve()
    if not project_dir.is_dir():
        raise BuildError(f"project directory not found: {project_dir}")

    pom = parse_pom(project_dir / "pom.xml")
    target = project_dir / "target"
    classes_dir = target / "classes"
    sbom_jars_dir = target / "sbom-jars"
    runtime_jars_dir = target / "runtime-jars"

    tools = toolchain(repo_root)
    env = build_env(repo_root)
    mvn = str(tools.maven)
    if not tools.maven.is_file():
        fallback = shutil.which("mvn", path=env.get("PATH"))
        if fallback is None:
            raise BuildError(f"Maven not found at {tools.maven}")
        mvn = fallback

    if not skip_build:
        _run([mvn, "-q", "-DskipTests", "package"], project_dir, env)
        _run(
            [
                mvn,
                "-q",
                "dependency:copy-dependencies",
                "-DincludeScope=test",
                f"-DoutputDirectory={sbom_jars_dir}",
            ],
            project_dir,
            env,
        )
        _run(
            [
                mvn,
                "-q",
                "dependency:copy-dependencies",
                "-DincludeScope=runtime",
                f"-DoutputDirectory={runtime_jars_dir}",
            ],
            project_dir,
            env,
        )

    missing = []
    if not classes_dir.is_dir():
        missing.append(str(classes_dir))
    if not sbom_jars_dir.is_dir():
        missing.append(str(sbom_jars_dir))
    if not runtime_jars_dir.is_dir():
        missing.append(str(runtime_jars_dir))
    if missing:
        raise BuildError(
            "build output is missing: " + ", ".join(missing) + "; run without --skip-build"
        )

    candidates = find_main_classes(classes_dir)
    main_class = choose_main_class(candidates, pom.artifact_id)

    return ProjectBuild(
        project_dir=project_dir,
        group_id=pom.group_id,
        artifact_id=pom.artifact_id,
        version=pom.version,
        main_class=main_class,
        classes_dir=classes_dir,
        sbom_jars_dir=sbom_jars_dir,
        runtime_jars_dir=runtime_jars_dir,
        main_classes=candidates,
    )
