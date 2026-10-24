#!/usr/bin/env python3
"""Prepare the Set C Spring Guides projects for the ReachSBOM evaluation.

The upstream guides track the newest Spring Boot release. To keep the Set C
comparison consistent, this script copies each guide's completed project and
pins the Spring Boot parent to 2.5.0. It also adds log4j-core 2.14.1 as a
compile dependency.

Three projects get a small startup logger that uses Log4j directly. The last
two get no added Log4j call. Original application code is kept except for one
startup wiring line in the plain Maven guide, which has no component runtime.

Usage:
    python3 evaluation/prepare_setc.py
    python3 evaluation/prepare_setc.py --build
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPOS = ROOT / "benchmarks" / "setC" / "repos"
APPS = ROOT / "benchmarks" / "setC" / "apps"
LOGS = ROOT / "benchmarks" / "setC" / "logs"
MANIFEST = ROOT / "benchmarks" / "setC" / "manifest.json"
DEFAULT_JAVA_HOME = ROOT / ".tools" / "jdk17"
DEFAULT_MAVEN = ROOT / ".tools" / "maven" / "bin" / "mvn"

POM_NS = "http://maven.apache.org/POM/4.0.0"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

# Spring Boot 4 renamed several starters. Boot 2.5.0 only knows the older
# names, so map the main runtime and test starters before building.
STARTER_COMPAT = {
    "spring-boot-starter-webmvc": "spring-boot-starter-web",
    "spring-boot-starter-data-jpa-test": "spring-boot-starter-test",
    "spring-boot-starter-webmvc-test": "spring-boot-starter-test",
    "spring-boot-starter-restclient": "spring-boot-starter-web",
    "spring-boot-starter-restclient-test": "spring-boot-starter-test",
}

PROJECTS = [
    {
        "name": "gs-spring-boot",
        "source_url": "https://github.com/spring-guides/gs-spring-boot.git",
        "project_dir": "complete",
        "package": "com.example.springboot",
        "logs": True,
        "expected_note": (
            "Spring Boot web app with an added Log4j startup call. "
            "log4j-core 2.14.1 is present in target/runtime-jars."
        ),
    },
    {
        "name": "gs-rest-service",
        "source_url": "https://github.com/spring-guides/gs-rest-service.git",
        "project_dir": "complete",
        "package": "com.example.restservice",
        "logs": True,
        "expected_note": (
            "Spring Boot REST app with an added Log4j startup call. "
            "log4j-core 2.14.1 is present in target/runtime-jars."
        ),
    },
    {
        "name": "gs-maven",
        "source_url": "https://github.com/spring-guides/gs-maven.git",
        "project_dir": "complete",
        "package": "hello",
        "logs": True,
        "expected_note": (
            "Plain Maven application, not Spring Boot. A Log4j startup call "
            "is wired into the existing main method."
        ),
    },
    {
        "name": "gs-validating-form-input",
        "source_url": "https://github.com/spring-guides/gs-validating-form-input.git",
        "project_dir": "complete",
        "package": "com.example.validatingforminput",
        "logs": True,
        "expected_note": (
            "Spring Boot form validation app with an added Log4j startup call. "
            "log4j-core 2.14.1 is present in target/runtime-jars."
        ),
    },
    {
        "name": "gs-accessing-data-jpa",
        "source_url": "https://github.com/spring-guides/gs-accessing-data-jpa.git",
        "project_dir": "complete",
        "package": "com.example.accessingdatajpa",
        "logs": False,
        "expected_note": (
            "Spring Boot JPA app. log4j-core 2.14.1 is present but the "
            "application does not log through Log4j."
        ),
    },
]


def qname(tag: str, namespace: str) -> str:
    return "{%s}%s" % (namespace, tag) if namespace else tag


def namespace_of(root: ET.Element) -> str:
    if root.tag.startswith("{"):
        return root.tag[1:].split("}", 1)[0]
    return ""


def child(element: ET.Element, name: str, namespace: str) -> ET.Element | None:
    return element.find(qname(name, namespace))


def set_child_text(element: ET.Element, name: str, namespace: str, value: str) -> None:
    node = child(element, name, namespace)
    if node is None:
        node = ET.SubElement(element, qname(name, namespace))
    node.text = value


def pin_boot_parent(root: ET.Element, namespace: str) -> bool:
    """Pin a Spring Boot parent or imported BOM to 2.5.0."""
    pinned = False
    parent = child(root, "parent", namespace)
    if parent is not None:
        artifact = child(parent, "artifactId", namespace)
        if artifact is not None and (artifact.text or "").strip() == "spring-boot-starter-parent":
            set_child_text(parent, "version", namespace, "2.5.0")
            pinned = True

    management = child(root, "dependencyManagement", namespace)
    if management is not None:
        dependencies = child(management, "dependencies", namespace)
        if dependencies is not None:
            for dependency in dependencies.findall(qname("dependency", namespace)):
                group = child(dependency, "groupId", namespace)
                artifact = child(dependency, "artifactId", namespace)
                if (
                    group is not None
                    and (group.text or "").strip() == "org.springframework.boot"
                    and artifact is not None
                    and (artifact.text or "").strip() == "spring-boot-dependencies"
                ):
                    set_child_text(dependency, "version", namespace, "2.5.0")
                    pinned = True
    return pinned


def map_boot_starters(root: ET.Element, namespace: str) -> list[str]:
    changes = []
    dependencies = child(root, "dependencies", namespace)
    if dependencies is None:
        return changes
    for dependency in dependencies.findall(qname("dependency", namespace)):
        artifact = child(dependency, "artifactId", namespace)
        if artifact is None or not artifact.text:
            continue
        if artifact.text.strip() == "spring-boot-starter-data-jpa-test":
            changes.append("removed spring-boot-starter-data-jpa-test")
            dependencies.remove(dependency)
            continue
        replacement = STARTER_COMPAT.get(artifact.text.strip())
        if replacement:
            changes.append("%s -> %s" % (artifact.text.strip(), replacement))
            artifact.text = replacement
    return changes


def add_log4j_dependency(root: ET.Element, namespace: str) -> None:
    dependencies = child(root, "dependencies", namespace)
    if dependencies is None:
        dependencies = ET.Element(qname("dependencies", namespace))
        build = child(root, "build", namespace)
        if build is not None:
            root.insert(list(root).index(build), dependencies)
        else:
            root.append(dependencies)

    for dependency in dependencies.findall(qname("dependency", namespace)):
        group = child(dependency, "groupId", namespace)
        artifact = child(dependency, "artifactId", namespace)
        if (
            group is not None
            and (group.text or "").strip() == "org.apache.logging.log4j"
            and artifact is not None
            and (artifact.text or "").strip() == "log4j-core"
        ):
            set_child_text(dependency, "version", namespace, "2.14.1")
            return

    dependency = ET.SubElement(dependencies, qname("dependency", namespace))
    ET.SubElement(dependency, qname("groupId", namespace)).text = "org.apache.logging.log4j"
    ET.SubElement(dependency, qname("artifactId", namespace)).text = "log4j-core"
    ET.SubElement(dependency, qname("version", namespace)).text = "2.14.1"


def patch_pom(pom: Path) -> list[str]:
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    tree = ET.parse(pom, parser=parser)
    root = tree.getroot()
    namespace = namespace_of(root)

    if namespace:
        ET.register_namespace("", namespace)
    if XSI_NS:
        ET.register_namespace("xsi", XSI_NS)

    notes = []
    pinned = pin_boot_parent(root, namespace)
    if pinned:
        notes.append("pinned Spring Boot parent/BOM to 2.5.0")
        notes.extend(map_boot_starters(root, namespace))
    add_log4j_dependency(root, namespace)
    notes.append("added log4j-core 2.14.1 compile dependency")

    ET.indent(tree, space="  ")
    tree.write(pom, encoding="UTF-8", xml_declaration=True)
    return notes


def fix_jakarta_imports(app: Path) -> int:
    changed = 0
    for path in (app / "src" / "main" / "java").rglob("*.java"):
        text = path.read_text(encoding="utf-8")
        updated = text
        for old, new in (
            ("jakarta.validation", "javax.validation"),
            ("jakarta.persistence", "javax.persistence"),
            ("jakarta.annotation", "javax.annotation"),
            ("jakarta.servlet", "javax.servlet"),
        ):
            updated = updated.replace(old, new)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed += 1
    return changed


def write_boot_logger(app: Path, package: str, name: str) -> None:
    package_dir = app / "src" / "main" / "java" / Path(*package.split("."))
    package_dir.mkdir(parents=True, exist_ok=True)
    source = """package {package};

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class StartupLogger implements ApplicationRunner {{

    private static final Logger LOGGER = LogManager.getLogger(StartupLogger.class);

    @Override
    public void run(ApplicationArguments args) {{
        LOGGER.info("ReachSBOM Set C startup marker: {name}");
    }}
}}
""".format(package=package, name=name)
    (package_dir / "StartupLogger.java").write_text(source, encoding="utf-8")


def write_plain_logger(app: Path, package: str, name: str) -> None:
    package_dir = app / "src" / "main" / "java" / Path(*package.split("."))
    package_dir.mkdir(parents=True, exist_ok=True)
    source = """package {package};

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class StartupLogger {{

    private static final Logger LOGGER = LogManager.getLogger(StartupLogger.class);

    private StartupLogger() {{
    }}

    public static void logStartup() {{
        LOGGER.info("ReachSBOM Set C startup marker: {name}");
    }}
}}
""".format(package=package, name=name)
    (package_dir / "StartupLogger.java").write_text(source, encoding="utf-8")


def write_log4j_config(app: Path) -> None:
    resources = app / "src" / "main" / "resources"
    resources.mkdir(parents=True, exist_ok=True)
    source = """<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d %-5p %c - %m%n"/>
        </Console>
    </Appenders>
    <Loggers>
        <Root level="info">
            <AppenderRef ref="Console"/>
        </Root>
    </Loggers>
</Configuration>
"""
    (resources / "log4j2.xml").write_text(source, encoding="utf-8")


def wire_plain_startup(app: Path) -> bool:
    main_file = app / "src" / "main" / "java" / "hello" / "HelloWorld.java"
    if not main_file.exists():
        return False
    text = main_file.read_text(encoding="utf-8")
    if "StartupLogger.logStartup();" in text:
        return False
    needle = "public static void main(String[] args) {"
    if needle not in text:
        return False
    replacement = needle + "\n\t\tStartupLogger.logStartup();"
    main_file.write_text(text.replace(needle, replacement, 1), encoding="utf-8")
    return True


def copy_project(project: dict) -> Path:
    source = REPOS / project["name"] / project["project_dir"]
    destination = APPS / project["name"]
    if not source.is_dir():
        raise FileNotFoundError("missing upstream project directory: %s" % source)
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(".git", "target", "build", ".gradle"),
    )
    return destination


def run_command(command: list[str], cwd: Path, env: dict, log_file: Path) -> tuple[int, str]:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=900,
    )
    log_file.write_text(process.stdout or "", encoding="utf-8")
    return process.returncode, process.stdout or ""


def build_project(project: dict, app: Path, maven: Path, env: dict) -> dict:
    pom = app / "pom.xml"
    result = {"status": "failed", "command": None, "reason": None}
    if not pom.exists():
        result["status"] = "not_built"
        result["reason"] = "no pom.xml; upstream project is Gradle only"
        return result

    package_command = [
        str(maven),
        "-q",
        "-DskipTests",
        # The upstream guide tests use Spring Boot 4 test APIs which do not
        # exist in 2.5.0. Skip test compilation as well as test execution.
        "-Dmaven.test.skip=true",
        "package",
    ]
    result["command"] = " ".join(package_command)
    code, output = run_command(
        package_command,
        app,
        env,
        LOGS / ("%s-package.log" % project["name"]),
    )
    if code != 0:
        result["reason"] = "mvn package failed with exit code %d" % code
        result["output_tail"] = output.strip().splitlines()[-12:]
        return result

    copy_commands = [
        [
            str(maven), "-q", "-DskipTests", "dependency:copy-dependencies",
            "-DincludeScope=compile", "-DoutputDirectory=target/sbom-jars",
        ],
        [
            str(maven), "-q", "-DskipTests", "dependency:copy-dependencies",
            "-DincludeScope=runtime", "-DoutputDirectory=target/runtime-jars",
        ],
    ]
    for index, command in enumerate(copy_commands):
        code, output = run_command(
            command,
            app,
            env,
            LOGS / ("%s-copy-%d.log" % (project["name"], index + 1)),
        )
        if code != 0:
            result["reason"] = "dependency:copy-dependencies failed with exit code %d" % code
            result["output_tail"] = output.strip().splitlines()[-12:]
            return result

    runtime_jars = sorted((app / "target" / "runtime-jars").glob("log4j-core-*.jar"))
    result["status"] = "built"
    result["runtime_log4j_core"] = [jar.name for jar in runtime_jars]
    if not runtime_jars:
        result["reason"] = "log4j-core was not copied to target/runtime-jars"
    return result


def write_manifest(projects: list[dict]) -> None:
    document = {
        "set": "C",
        "description": (
            "Real Spring Guides projects prepared with log4j-core 2.14.1. "
            "The first three add a Log4j startup call; the last two do not."
        ),
        "preparation": {
            "script": "evaluation/prepare_setc.py",
            "spring_boot_version": "2.5.0",
            "log4j_core_version": "2.14.1",
            "build_command": (
                "mvn -q -DskipTests -Dmaven.test.skip=true package"
            ),
        },
        "projects": projects,
    }
    MANIFEST.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help="build the prepared projects")
    parser.add_argument("--maven", default=str(DEFAULT_MAVEN), help="path to the mvn executable")
    parser.add_argument("--java-home", default=str(DEFAULT_JAVA_HOME), help="path to a JDK")
    args = parser.parse_args()

    APPS.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    java_home = Path(args.java_home)
    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")

    projects = []
    for definition in PROJECTS:
        app = copy_project(definition)
        notes = []
        pom = app / "pom.xml"
        fixed = fix_jakarta_imports(app)
        if fixed:
            notes.append("mapped jakarta.validation imports to javax.validation")
        if pom.exists():
            notes.extend(patch_pom(pom))
        if definition["logs"]:
            if definition["project_dir"] == "complete" and definition["name"] != "gs-maven":
                write_boot_logger(app, definition["package"], definition["name"])
                notes.append("added Spring ApplicationRunner startup logger")
            else:
                write_plain_logger(app, definition["package"], definition["name"])
                if wire_plain_startup(app):
                    notes.append("wired StartupLogger into HelloWorld.main")
                else:
                    notes.append("added plain startup logger")
            write_log4j_config(app)
            notes.append("added log4j2.xml with an INFO console appender")

        entry = {
            "name": definition["name"],
            "source_url": definition["source_url"],
            "project_dir": definition["project_dir"],
            "app_path": str(app.relative_to(ROOT)),
            "logs": definition["logs"],
            "expected_note": definition["expected_note"],
            "preparation_notes": notes,
        }
        projects.append(entry)
        print("[prepared] %s -> %s" % (definition["name"], app.relative_to(ROOT)))

    if args.build:
        maven = Path(args.maven)
        for entry in projects:
            app = ROOT / entry["app_path"]
            print("[build] %s" % entry["name"])
            result = build_project(entry, app, maven, env)
            entry["build"] = result
            print("  status: %s" % result["status"])
            if result.get("reason"):
                print("  reason: %s" % result["reason"])

    write_manifest(projects)

    if args.build:
        print("\nBuild summary:")
        for entry in projects:
            build = entry.get("build", {})
            print("  %-22s %s" % (entry["name"], build.get("status", "unknown")))
            for jar in build.get("runtime_log4j_core", []):
                print("  %-22s runtime jar: %s" % ("", jar))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
