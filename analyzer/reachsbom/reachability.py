from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import stage2
from .maven import build_env, find_repo_root, toolchain
from .models import (
    Advisory,
    ProjectBuild,
    ReachsbomError,
    SymbolRef,
    SymbolResult,
    base_purl,
    purl_name,
)


EDGE_RULE_CVES = {"CVE-2021-44228": "log4j-shell"}
KNOWN_STATUSES = {
    "Present",
    "ClassPresent",
    "PossiblyReachable",
    "Reachable",
    "Taint",
}


class AnalyzerError(ReachsbomError):
    pass


def load_static_advisories(path: Path) -> list[Advisory]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalyzerError(f"cannot read advisory symbol data {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AnalyzerError(f"advisory symbol data must be an object: {path}")

    advisories = []
    for advisory_id, item in data.items():
        if not isinstance(item, dict):
            continue
        symbols = []
        for symbol in item.get("symbols") or []:
            if not isinstance(symbol, dict):
                continue
            class_name = str(symbol.get("class") or "")
            if not class_name:
                continue
            methods = tuple(
                str(method) for method in symbol.get("methods") or [] if method
            )
            symbols.append(SymbolRef(advisory_id, class_name, methods))
        purl = str(item.get("component") or "")
        aliases = []
        if item.get("ghsa"):
            aliases.append(str(item["ghsa"]))
        advisories.append(
            Advisory(
                advisory_id=advisory_id,
                purl=purl,
                component=purl_name(purl),
                cvss=float(item.get("cvss") or 0.0),
                fixed_version=str(item.get("fixed") or ""),
                summary=str(item.get("summary") or ""),
                aliases=aliases,
                symbols=symbols,
                source=str(item.get("source") or "symbol map"),
            )
        )
    return advisories


def attach_static_symbols(
    advisories: list[Advisory],
    static_advisories: list[Advisory],
) -> list[Advisory]:
    for advisory in advisories:
        matches = []
        for candidate in static_advisories:
            same_id = bool(set(advisory.all_ids()) & set(candidate.all_ids()))
            same_component = base_purl(advisory.purl) == base_purl(candidate.purl)
            if same_id and same_component:
                matches.append(candidate)
        if not matches:
            continue

        symbols = []
        seen = set()
        for match in matches:
            for symbol in match.symbols:
                key = (symbol.class_name, symbol.methods)
                if key not in seen:
                    seen.add(key)
                    symbols.append(
                        SymbolRef(advisory.advisory_id, symbol.class_name, symbol.methods)
                    )
        advisory.symbols = symbols
        if not advisory.cvss and matches[0].cvss:
            advisory.cvss = matches[0].cvss
        if not advisory.fixed_version and matches[0].fixed_version:
            advisory.fixed_version = matches[0].fixed_version
        if not advisory.summary and matches[0].summary:
            advisory.summary = matches[0].summary
        for match in matches:
            for alias in match.aliases:
                if alias not in advisory.aliases:
                    advisory.aliases.append(alias)
    return advisories


def load_edge_rules(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalyzerError(f"cannot read edge rules {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AnalyzerError(f"edge rules must be an object: {path}")
    return data


def edge_rules_for(
    advisories: list[Advisory],
    path: Path,
    enabled: bool = True,
) -> list[dict]:
    if not enabled:
        return []
    groups = load_edge_rules(path)
    present_ids = {item for advisory in advisories for item in advisory.all_ids()}
    rules = []
    seen = set()
    for advisory_id, group in EDGE_RULE_CVES.items():
        if advisory_id not in present_ids:
            continue
        for rule in groups.get(group) or []:
            if not isinstance(rule, dict):
                continue
            key = json.dumps(rule, sort_keys=True)
            if key not in seen:
                seen.add(key)
                rules.append(rule)
    return rules


def _app_id(build: ProjectBuild) -> str:
    value = f"{build.artifact_id}-{build.version}"
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return cleaned or "app"


def build_request(
    build: ProjectBuild,
    advisories: list[Advisory],
    runtime_index: stage2.RuntimeIndex | None = None,
    algorithm: str = "rta",
    use_edge_rules: bool = True,
    edge_rules_path: Path | None = None,
    repo_root: Path | None = None,
) -> dict:
    if algorithm not in ("rta", "cha"):
        raise AnalyzerError(f"unsupported algorithm: {algorithm}")
    root = find_repo_root(repo_root)
    rules_path = edge_rules_path or (root / "data" / "edge_rules.json")

    symbols = []
    for advisory in advisories:
        for symbol in advisory.symbols:
            if runtime_index is not None and not runtime_index.has_class(symbol.class_name):
                continue
            methods = [method for method in symbol.methods if method]
            if not methods:
                continue
            symbols.append(
                {
                    "key": advisory.advisory_id,
                    "class": symbol.class_name,
                    "methods": methods,
                }
            )

    return {
        "algorithm": algorithm,
        "use_edge_rules": use_edge_rules,
        "apps": [
            {
                "id": _app_id(build),
                "main_class": build.main_class,
                "app_dirs": [str(build.classes_dir.resolve())],
                "runtime_jars": [str(jar.resolve()) for jar in build.runtime_jars()],
                "symbols": symbols,
                "edge_rules": edge_rules_for(
                    advisories,
                    rules_path,
                    enabled=use_edge_rules,
                ),
                "reflection": True,
            }
        ],
    }


def analyzer_jar_path(repo_root: Path | None = None) -> Path:
    configured = os.environ.get("REACHSBOM_ANALYZER_JAR")
    if configured:
        return Path(configured).expanduser().resolve()
    root = find_repo_root(repo_root)
    return root / "java-analyzer" / "target" / "reachsbom-analyzer.jar"


def run_analyzer(
    request: dict,
    out_dir: Path,
    analyzer_jar: Path | None = None,
    repo_root: Path | None = None,
) -> dict:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    request_path = out_dir / "request.json"
    response_path = out_dir / "response.json"
    request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")

    jar = (analyzer_jar or analyzer_jar_path(repo_root)).resolve()
    if not jar.is_file():
        raise AnalyzerError(
            f"Java analyzer jar not found at {jar}; run scripts/build_java.sh"
        )

    tools = toolchain(repo_root)
    env = build_env(repo_root)
    java = str(tools.java)
    if not tools.java.is_file():
        fallback = shutil.which("java", path=env.get("PATH"))
        if fallback is None:
            raise AnalyzerError(f"java not found at {tools.java}")
        java = fallback

    command = [
        java,
        "-Xmx3g",
        "-jar",
        str(jar),
        "--request",
        str(request_path),
        "--output",
        str(response_path),
    ]
    completed = subprocess.run(
        command,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        output = (completed.stderr or completed.stdout or "").strip()
        tail = "\n".join(output.splitlines()[-30:])
        raise AnalyzerError(
            f"Java analyzer failed with exit code {completed.returncode}\n{tail}"
        )
    if not response_path.is_file():
        raise AnalyzerError(f"Java analyzer did not write {response_path}")
    try:
        response = json.loads(response_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalyzerError(f"cannot read analyzer response {response_path}: {exc}") from exc
    if not isinstance(response, dict):
        raise AnalyzerError("analyzer response is not a JSON object")
    return response


def _select_app(response: dict, app_id: str | None = None) -> tuple[dict, dict]:
    apps = response.get("apps")
    if not isinstance(apps, dict) or not apps:
        return {}, {}
    if app_id and isinstance(apps.get(app_id), dict):
        node = apps[app_id]
        return node, node.get("symbols") if isinstance(node.get("symbols"), dict) else {}
    first = next(iter(apps.values()))
    if not isinstance(first, dict):
        return {}, {}
    symbols = first.get("symbols")
    return first, symbols if isinstance(symbols, dict) else {}


def parse_analyzer_response(response: dict, app_id: str | None = None) -> dict[str, dict]:
    node, symbols = _select_app(response, app_id)
    if isinstance(symbols, list):
        converted = {}
        for item in symbols:
            if not isinstance(item, dict):
                continue
            key = item.get("method") or item.get("key") or item.get("signature")
            if key:
                converted[str(key)] = item
        return converted
    result = {}
    for key, value in symbols.items():
        if isinstance(value, dict):
            result[str(key)] = value
    return result


def _normalise_status(value: str) -> str:
    for status in KNOWN_STATUSES:
        if str(value).lower() == status.lower():
            return status
    return "Present"


def _method_result(
    advisory: Advisory,
    symbol: SymbolRef,
    method: str,
    entry: dict,
    app_dynamic: bool,
) -> SymbolResult:
    status = _normalise_status(str(entry.get("status") or "Present"))
    class_present = bool(entry.get("class_present", True))
    method_present = bool(entry.get("method_present", False))
    if not class_present:
        status = "Present"
    path = [str(item) for item in entry.get("path") or []]
    return SymbolResult(
        advisory_id=advisory.advisory_id,
        class_name=symbol.class_name,
        method=str(entry.get("method") or method),
        status=status,
        path=path,
        dynamic=bool(entry.get("dynamic", app_dynamic)),
        class_present=class_present,
        method_present=method_present,
        source="java",
        purl=advisory.purl,
    )


def analyze(
    build: ProjectBuild,
    advisories: list[Advisory],
    runtime_index: stage2.RuntimeIndex,
    out_dir: Path,
    algorithm: str = "rta",
    use_edge_rules: bool = True,
    edge_rules_path: Path | None = None,
    analyzer_jar: Path | None = None,
    repo_root: Path | None = None,
) -> list[SymbolResult]:
    request = build_request(
        build,
        advisories,
        runtime_index,
        algorithm=algorithm,
        use_edge_rules=use_edge_rules,
        edge_rules_path=edge_rules_path,
        repo_root=repo_root,
    )

    results: list[SymbolResult] = []
    requested = request["apps"][0]["symbols"]
    response: dict = {}
    if requested:
        response = run_analyzer(
            request,
            out_dir,
            analyzer_jar=analyzer_jar,
            repo_root=repo_root,
        )
    else:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "request.json").write_text(
            json.dumps(request, indent=2) + "\n", encoding="utf-8"
        )

    app_node, _ = _select_app(response)
    app_dynamic = bool(app_node.get("dynamic", False))
    active = parse_analyzer_response(response)

    for advisory in advisories:
        if not advisory.symbols:
            present = runtime_index.component_present(advisory.purl)
            results.append(
                SymbolResult(
                    advisory_id=advisory.advisory_id,
                    class_name="",
                    method="",
                    status="ClassPresent" if present else "Present",
                    class_present=present,
                    method_present=False,
                    source="component",
                    purl=advisory.purl,
                )
            )
            continue
        for symbol in advisory.symbols:
            class_present = runtime_index.has_class(symbol.class_name)
            for method in symbol.methods:
                if not class_present:
                    results.append(
                        SymbolResult(
                            advisory_id=advisory.advisory_id,
                            class_name=symbol.class_name,
                            method=method,
                            status="Present",
                            class_present=False,
                            method_present=False,
                            source="stage2",
                            purl=advisory.purl,
                        )
                    )
                    continue
                entry = active.get(method)
                if entry is None:
                    results.append(
                        SymbolResult(
                            advisory_id=advisory.advisory_id,
                            class_name=symbol.class_name,
                            method=method,
                            status="ClassPresent",
                            class_present=True,
                            method_present=False,
                            source="java-missing",
                            purl=advisory.purl,
                        )
                    )
                    continue
                results.append(
                    _method_result(advisory, symbol, method, entry, app_dynamic)
                )

    stage2.apply_component_fallback(results, runtime_index)
    return results
