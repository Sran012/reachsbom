#!/usr/bin/env python3
"""Generate the seeded Set A benchmark for ReachSBOM.

Set A contains 30 tiny Maven applications. Each vulnerable library gets the
same ten usage patterns so that reachability results can be compared across
libraries and across patterns.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SET_A_DIR = REPO_ROOT / "benchmarks" / "setA"
PARENT_GROUP_ID = "io.reachsbom.setA"
PARENT_ARTIFACT_ID = "seta-parent"
PARENT_VERSION = "1.0"
SPI_ARTIFACT_ID = "seta-spi"

LIB_ORDER = ("log4j", "commons", "snakeyaml")

LIBRARIES = {
    "log4j": {
        "library": "log4j-core",
        "group": "org.apache.logging.log4j",
        "artifact": "log4j-core",
        "version": "2.14.1",
        "cve": "CVE-2021-44228",
        "jars": [
            "log4j-core-2.14.1.jar",
            "log4j-api-2.14.1.jar",
        ],
        "direct": (
            'org.apache.logging.log4j.core.net.JndiManager.getDefaultManager()'
            '.lookup("ldap://127.0.0.1:1389/x");'
        ),
        "checked": True,
        "reflect_class": "org.apache.logging.log4j.core.lookup.JndiLookup",
        "reflect_method": "lookup",
        "reflect_params": (
            "org.apache.logging.log4j.core.LogEvent.class, String.class"
        ),
        "reflect_args": 'null, "x"',
    },
    "commons": {
        "library": "commons-text",
        "group": "org.apache.commons",
        "artifact": "commons-text",
        "version": "1.9",
        "cve": "CVE-2022-42889",
        "jars": [
            "commons-text-1.9.jar",
            "commons-lang3-3.11.jar",
        ],
        "direct": (
            'new org.apache.commons.text.StringSubstitutor().replace("${x}");'
        ),
        "checked": False,
        "reflect_class": "org.apache.commons.text.StringSubstitutor",
        "reflect_method": "replace",
        "reflect_params": "String.class",
        "reflect_args": '"${x}"',
    },
    "snakeyaml": {
        "library": "snakeyaml",
        "group": "org.yaml",
        "artifact": "snakeyaml",
        "version": "1.33",
        "cve": "CVE-2022-1471",
        "jars": [
            "snakeyaml-1.33.jar",
        ],
        "direct": 'Object o = new org.yaml.snakeyaml.Yaml().load("a: 1");',
        "checked": False,
        "reflect_class": "org.yaml.snakeyaml.Yaml",
        "reflect_method": "load",
        "reflect_params": "String.class",
        "reflect_args": '"a: 1"',
    },
}

EXPECTED_BY_PATTERN = {
    1: "Present",
    2: "ClassPresent",
    3: "Reachable",
    4: "Reachable",
    5: "Reachable",
    6: "Reachable",
    7: "PossiblyReachable",
    8: "ClassPresent",
    9: "ClassPresent",
    10: "Reachable",
}

SERVICE_LOADER_RULE = {
    "type": "service_loader",
    "interface": "seta.spi.Plugin",
    "method": "run",
}


def app_id(lib_key: str, pattern: int) -> str:
    return f"{lib_key}-p{pattern}"


def package_name(lib_key: str, pattern: int) -> str:
    return f"seta.{lib_key}.p{pattern}"


def app_dir(lib_key: str, pattern: int) -> Path:
    return SET_A_DIR / app_id(lib_key, pattern)


def java_source(
    package: str, body_lines: list[str], imports: list[str] | None = None
) -> str:
    lines = [f"package {package};", ""]
    if imports:
        lines.extend(f"import {import_name};" for import_name in imports)
        lines.append("")
    lines.extend(body_lines)
    return "\n".join(lines) + "\n"


def throws_clause(lib: dict, force: bool = False) -> str:
    return " throws Exception" if force or lib["checked"] else ""


def direct_call(lib: dict, spaces: int) -> list[str]:
    return [" " * spaces + lib["direct"]]


def reflection_call(lib: dict, spaces: int, dynamic_class: bool) -> list[str]:
    pad = " " * spaces
    if dynamic_class:
        class_line = f"{pad}Class<?> clazz = Class.forName(args[0]);"
    else:
        class_line = (
            f'{pad}Class<?> clazz = Class.forName("{lib["reflect_class"]}");'
        )
    return [
        class_line,
        f"{pad}Object instance = clazz.getDeclaredConstructor().newInstance();",
        (
            f"{pad}java.lang.reflect.Method method = clazz.getMethod("
            f'"{lib["reflect_method"]}", {lib["reflect_params"]});'
        ),
        f"{pad}method.invoke(instance, {lib['reflect_args']});",
    ]


def app_source(lib_key: str, pattern: int) -> tuple[str, list[tuple[str, str]]]:
    """Return the App source and any extra files as (relative path, text)."""
    lib = LIBRARIES[lib_key]
    package = package_name(lib_key, pattern)
    label = app_id(lib_key, pattern)
    main_throws = throws_clause(lib, force=pattern in (6, 7))
    body: list[str] = [
        "public final class App {",
        "    private App() {",
        "    }",
        "",
        f"    public static void main(String[] args){main_throws} {{",
    ]

    if pattern in (1, 2):
        scope = "provided" if pattern == 1 else "compile"
        body.append(
            f'        System.out.println("{label}: {scope} dependency is never referenced");'
        )
    elif pattern == 3:
        body.append("        " + lib["direct"])
    elif pattern == 4:
        body.append("        step1();")
        body.extend(
            [
                "    }",
                "",
                f"    private static void step1(){main_throws} {{",
                "        step2();",
                "    }",
                "",
                f"    private static void step2(){main_throws} {{",
                "        step3();",
                "    }",
                "",
                f"    private static void step3(){main_throws} {{",
            ]
        )
        body.extend(direct_call(lib, 8))
    elif pattern == 5:
        body.append("        Action action = new ActionImpl();")
        body.append("        action.run();")
    elif pattern == 6:
        body.extend(reflection_call(lib, 8, dynamic_class=False))
    elif pattern == 7:
        body.extend(reflection_call(lib, 8, dynamic_class=True))
    elif pattern == 8:
        body.append(
            f'        System.out.println("{label}: vulnerable call is never reached");'
        )
        body.extend(
            [
                "    }",
                "",
                f"    private static void unused(){main_throws} {{",
            ]
        )
        body.extend(direct_call(lib, 8))
    elif pattern == 9:
        body.append(
            f'        System.out.println("{label}: vulnerable call is only in test sources");'
        )
    elif pattern == 10:
        if lib_key == "log4j":
            body.append(
                '        org.apache.logging.log4j.LogManager.getLogger(App.class)'
                '.error("${jndi:ldap://127.0.0.1:1389/x}");'
            )
        else:
            body.append("        ServiceLoader.load(Plugin.class).forEach(Plugin::run);")
    else:
        raise ValueError(f"unknown pattern: {pattern}")

    body.extend(["    }", "}"])

    imports: list[str] = []
    if pattern == 10 and lib_key != "log4j":
        imports = ["java.util.ServiceLoader", "seta.spi.Plugin"]

    main_text = java_source(package, body, imports)
    package_path = package.replace(".", "/")
    extra_files: list[tuple[str, str]] = []

    if pattern == 5:
        action_throws = throws_clause(lib)
        extra_files.append(
            (
                f"src/main/java/{package_path}/Action.java",
                java_source(
                    package,
                    [
                        "public interface Action {",
                        f"    void run(){action_throws};",
                        "}",
                    ],
                ),
            )
        )
        extra_files.append(
            (
                f"src/main/java/{package_path}/ActionImpl.java",
                java_source(
                    package,
                    [
                        "public final class ActionImpl implements Action {",
                        "    @Override",
                        f"    public void run(){action_throws} {{",
                    ]
                    + direct_call(lib, 8)
                    + ["    }", "}"],
                ),
            )
        )
    elif pattern == 9:
        test_throws = throws_clause(lib)
        extra_files.append(
            (
                f"src/test/java/{package_path}/P9Call.java",
                java_source(
                    package,
                    [
                        "final class P9Call {",
                        "    private P9Call() {",
                        "    }",
                        "",
                        f"    static void run(){test_throws} {{",
                    ]
                    + direct_call(lib, 8)
                    + ["    }", "}"],
                ),
            )
        )
    elif pattern == 10 and lib_key != "log4j":
        extra_files.append(
            (
                f"src/main/java/{package_path}/PluginImpl.java",
                java_source(
                    package,
                    [
                        "public final class PluginImpl implements Plugin {",
                        "    @Override",
                        f"    public void run(){throws_clause(lib)} {{",
                    ]
                    + direct_call(lib, 8)
                    + ["    }", "}"],
                    ["seta.spi.Plugin"],
                ),
            )
        )
        extra_files.append(
            (
                "src/main/resources/META-INF/services/seta.spi.Plugin",
                f"{package}.PluginImpl\n",
            )
        )
    return main_text, extra_files


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parent_pom() -> str:
    modules = ["    <module>spi</module>"]
    for lib_key in LIB_ORDER:
        for pattern in range(1, 11):
            modules.append(f"    <module>{app_id(lib_key, pattern)}</module>")

    return "\n".join(
        [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<project xmlns="http://maven.apache.org/POM/4.0.0"',
            '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 '
            'https://maven.apache.org/xsd/maven-4.0.0.xsd">',
            "  <modelVersion>4.0.0</modelVersion>",
            "",
            f"  <groupId>{PARENT_GROUP_ID}</groupId>",
            f"  <artifactId>{PARENT_ARTIFACT_ID}</artifactId>",
            f"  <version>{PARENT_VERSION}</version>",
            "  <packaging>pom</packaging>",
            "  <name>ReachSBOM Set A</name>",
            "",
            "  <properties>",
            "    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>",
            "    <maven.compiler.release>8</maven.compiler.release>",
            "  </properties>",
            "",
            "  <modules>",
            *modules,
            "  </modules>",
            "",
            "  <dependencyManagement>",
            "    <dependencies>",
            "      <dependency>",
            "        <groupId>org.apache.logging.log4j</groupId>",
            "        <artifactId>log4j-core</artifactId>",
            "        <version>2.14.1</version>",
            "      </dependency>",
            "      <dependency>",
            "        <groupId>org.apache.commons</groupId>",
            "        <artifactId>commons-text</artifactId>",
            "        <version>1.9</version>",
            "      </dependency>",
            "      <dependency>",
            "        <groupId>org.yaml</groupId>",
            "        <artifactId>snakeyaml</artifactId>",
            "        <version>1.33</version>",
            "      </dependency>",
            "      <dependency>",
            f"        <groupId>{PARENT_GROUP_ID}</groupId>",
            f"        <artifactId>{SPI_ARTIFACT_ID}</artifactId>",
            f"        <version>{PARENT_VERSION}</version>",
            "      </dependency>",
            "    </dependencies>",
            "  </dependencyManagement>",
            "",
            "  <build>",
            "    <pluginManagement>",
            "      <plugins>",
            "        <plugin>",
            "          <groupId>org.apache.maven.plugins</groupId>",
            "          <artifactId>maven-compiler-plugin</artifactId>",
            "          <version>3.8.1</version>",
            "        </plugin>",
            "        <plugin>",
            "          <groupId>org.apache.maven.plugins</groupId>",
            "          <artifactId>maven-surefire-plugin</artifactId>",
            "          <version>3.2.5</version>",
            "        </plugin>",
            "        <plugin>",
            "          <groupId>org.apache.maven.plugins</groupId>",
            "          <artifactId>maven-dependency-plugin</artifactId>",
            "          <version>3.7.0</version>",
            "        </plugin>",
            "      </plugins>",
            "    </pluginManagement>",
            "  </build>",
            "</project>",
            "",
        ]
    )


def child_pom(lib_key: str, pattern: int) -> str:
    lib = LIBRARIES[lib_key]
    identifier = app_id(lib_key, pattern)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<project xmlns="http://maven.apache.org/POM/4.0.0"',
        '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
        '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 '
        'https://maven.apache.org/xsd/maven-4.0.0.xsd">',
        "  <modelVersion>4.0.0</modelVersion>",
        "",
        "  <parent>",
        f"    <groupId>{PARENT_GROUP_ID}</groupId>",
        f"    <artifactId>{PARENT_ARTIFACT_ID}</artifactId>",
        f"    <version>{PARENT_VERSION}</version>",
        "  </parent>",
        "",
        f"  <artifactId>{identifier}</artifactId>",
        f"  <name>Set A {identifier}</name>",
        "",
        "  <dependencies>",
        "    <dependency>",
        f"      <groupId>{lib['group']}</groupId>",
        f"      <artifactId>{lib['artifact']}</artifactId>",
    ]
    if pattern == 1:
        lines.append("      <scope>provided</scope>")
    lines.extend(
        [
            "    </dependency>",
        ]
    )
    if pattern == 10 and lib_key != "log4j":
        lines.extend(
            [
                "    <dependency>",
                f"      <groupId>{PARENT_GROUP_ID}</groupId>",
                f"      <artifactId>{SPI_ARTIFACT_ID}</artifactId>",
                "    </dependency>",
            ]
        )
    lines.extend(
        [
            "  </dependencies>",
            "</project>",
            "",
        ]
    )
    return "\n".join(lines)


def spi_pom() -> str:
    return "\n".join(
        [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<project xmlns="http://maven.apache.org/POM/4.0.0"',
            '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 '
            'https://maven.apache.org/xsd/maven-4.0.0.xsd">',
            "  <modelVersion>4.0.0</modelVersion>",
            "",
            "  <parent>",
            f"    <groupId>{PARENT_GROUP_ID}</groupId>",
            f"    <artifactId>{PARENT_ARTIFACT_ID}</artifactId>",
            f"    <version>{PARENT_VERSION}</version>",
            "  </parent>",
            "",
            f"  <artifactId>{SPI_ARTIFACT_ID}</artifactId>",
            "  <name>Set A service provider interface</name>",
            "</project>",
            "",
        ]
    )


def load_log4j_edge_rules() -> list[dict]:
    edge_rules_path = REPO_ROOT / "data" / "edge_rules.json"
    with edge_rules_path.open(encoding="utf-8") as handle:
        rules = json.load(handle)
    return rules["log4j-shell"]


def manifest_entry(lib_key: str, pattern: int, log4j_edge_rules: list[dict]) -> dict:
    lib = LIBRARIES[lib_key]
    identifier = app_id(lib_key, pattern)

    sbom_jars = [
        f"{identifier}/target/sbom-jars/{jar}" for jar in lib["jars"]
    ]
    runtime_jars: list[str] = []
    if pattern != 1:
        runtime_jars = [
            f"{identifier}/target/runtime-jars/{jar}" for jar in lib["jars"]
        ]
    if pattern == 10 and lib_key != "log4j":
        sbom_jars.append(f"{identifier}/target/sbom-jars/{SPI_ARTIFACT_ID}-1.0.jar")
        runtime_jars.append(
            f"{identifier}/target/runtime-jars/{SPI_ARTIFACT_ID}-1.0.jar"
        )

    edge_rules: list[dict] = []
    if pattern == 10 and lib_key == "log4j":
        edge_rules = log4j_edge_rules
    elif pattern == 10:
        edge_rules = [dict(SERVICE_LOADER_RULE)]

    return {
        "id": identifier,
        "library": lib["library"],
        "cve": lib["cve"],
        "pattern": f"P{pattern}",
        "expected": EXPECTED_BY_PATTERN[pattern],
        "main_class": f"{package_name(lib_key, pattern)}.App",
        "app_dir": identifier,
        "runtime_jars": runtime_jars,
        "sbom_jars": sbom_jars,
        "edge_rules": edge_rules,
    }


def write_app(lib_key: str, pattern: int) -> None:
    directory = app_dir(lib_key, pattern)
    package_path = package_name(lib_key, pattern).replace(".", "/")
    main_text, extra_files = app_source(lib_key, pattern)
    write_text(directory / "pom.xml", child_pom(lib_key, pattern))
    write_text(
        directory / "src/main/java" / package_path / "App.java", main_text
    )
    for relative_path, text in extra_files:
        write_text(directory / relative_path, text)


def main() -> None:
    SET_A_DIR.mkdir(parents=True, exist_ok=True)

    # Remove only the directories owned by the generator so a rerun cannot
    # leave stale sources or build outputs behind.
    for lib_key in LIB_ORDER:
        for pattern in range(1, 11):
            directory = app_dir(lib_key, pattern)
            if directory.exists():
                shutil.rmtree(directory)
    spi_dir = SET_A_DIR / "spi"
    if spi_dir.exists():
        shutil.rmtree(spi_dir)

    log4j_edge_rules = load_log4j_edge_rules()
    manifest: list[dict] = []

    write_text(SET_A_DIR / "pom.xml", parent_pom())

    write_text(spi_dir / "pom.xml", spi_pom())
    write_text(
        spi_dir / "src/main/java/seta/spi/Plugin.java",
        java_source("seta.spi", ["public interface Plugin {", "    void run();", "}"]),
    )

    for lib_key in LIB_ORDER:
        for pattern in range(1, 11):
            write_app(lib_key, pattern)
            manifest.append(manifest_entry(lib_key, pattern, log4j_edge_rules))

    manifest_path = SET_A_DIR / "manifest.json"
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")

    print(f"Wrote {len(manifest)} Set A applications to {SET_A_DIR}")
    print(f"Wrote {manifest_path}")


if __name__ == "__main__":
    main()
