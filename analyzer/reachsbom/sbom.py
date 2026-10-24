from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .maven import build_env, toolchain
from .models import (
    Component,
    ProjectBuild,
    ReachsbomError,
    add_purl_version,
    purl_name,
    purl_namespace,
    purl_version,
)


class SbomError(ReachsbomError):
    pass


@dataclass
class Sbom:
    path: Path
    components: list[Component]
    document: dict


def _syft_command(repo_root: Path | None) -> str:
    tools = toolchain(repo_root)
    if tools.syft.is_file():
        return str(tools.syft)
    found = shutil.which("syft")
    if found:
        return found
    raise SbomError(f"syft not found at {tools.syft}")


def _project_component(build: ProjectBuild) -> dict:
    purl = build.purl
    return {
        "type": "library",
        "bom-ref": purl,
        "group": build.group_id,
        "name": build.artifact_id,
        "version": build.version,
        "purl": purl,
    }


def _component_purl(component: dict) -> str:
    purl = str(component.get("purl") or "")
    version = str(component.get("version") or "")
    if purl and version and not purl_version(purl):
        purl = add_purl_version(purl, version)
    return purl


def parse_components(document: dict) -> list[Component]:
    result: list[Component] = []
    seen = set()
    for item in document.get("components") or []:
        if not isinstance(item, dict):
            continue
        purl = _component_purl(item)
        if not purl.startswith("pkg:"):
            continue
        if purl in seen:
            continue
        seen.add(purl)
        name = str(item.get("name") or purl_name(purl))
        group = str(item.get("group") or purl_namespace(purl))
        version = str(item.get("version") or purl_version(purl))
        scope = str(item.get("scope") or "")
        result.append(Component(name=name, version=version, purl=purl, group=group, scope=scope))
    return result


def build_sbom(
    build: ProjectBuild,
    out_path: Path,
    repo_root: Path | None = None,
) -> Sbom:
    syft = _syft_command(repo_root)
    jars_dir = build.sbom_jars_dir
    if not jars_dir.is_dir():
        raise SbomError(f"dependency directory not found: {jars_dir}")

    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        syft,
        str(jars_dir.resolve()),
        "-o",
        f"cyclonedx-json={out_path}",
        "-q",
    ]
    completed = subprocess.run(
        command,
        cwd=build.project_dir,
        env=build_env(repo_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        output = (completed.stderr or completed.stdout or "").strip()
        tail = "\n".join(output.splitlines()[-20:])
        raise SbomError(
            f"syft failed with exit code {completed.returncode}\n{tail}"
        )
    if not out_path.is_file():
        raise SbomError(f"syft did not write {out_path}")

    try:
        document = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SbomError(f"cannot read syft output {out_path}: {exc}") from exc

    components = document.get("components")
    if not isinstance(components, list):
        components = []
        document["components"] = components
    project = _project_component(build)
    project_base = build.purl.rsplit("@", 1)[0]
    present = any(
        isinstance(item, dict)
        and str(item.get("purl") or "").rsplit("@", 1)[0] == project_base
        for item in components
    )
    if not present:
        components.insert(0, project)

    try:
        out_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise SbomError(f"cannot write {out_path}: {exc}") from exc

    return Sbom(path=out_path, components=parse_components(document), document=document)
