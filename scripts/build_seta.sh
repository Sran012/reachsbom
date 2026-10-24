#!/usr/bin/env bash
# Build all Set A applications and materialize their dependency jars.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SET_A_DIR="$REPO_ROOT/benchmarks/setA"
MAVEN_HOME="$REPO_ROOT/.tools/maven"
JAVA_HOME="${JAVA_HOME:-$REPO_ROOT/.tools/jdk17}"
MVN="${MVN:-$MAVEN_HOME/bin/mvn}"
PYTHON="${PYTHON:-python3}"

if [[ ! -x "$JAVA_HOME/bin/java" ]]; then
    echo "ERROR: JAVA_HOME does not point to a JDK: $JAVA_HOME" >&2
    exit 1
fi
if [[ ! -x "$MVN" ]]; then
    echo "ERROR: Maven executable not found: $MVN" >&2
    exit 1
fi
if [[ ! -f "$SET_A_DIR/pom.xml" ]]; then
    echo "ERROR: Set A parent pom not found: $SET_A_DIR/pom.xml" >&2
    echo "Run evaluation/generate_seta.py first." >&2
    exit 1
fi

export JAVA_HOME
export PATH="$JAVA_HOME/bin:$MAVEN_HOME/bin:$PATH"
export MAVEN_OPTS="${MAVEN_OPTS:-}"

echo "Building Set A with $MVN"
echo "JAVA_HOME=$JAVA_HOME"
if ! "$MVN" -f "$SET_A_DIR/pom.xml" clean install -DskipTests; then
    echo "ERROR: the Set A parent build failed. No results were produced." >&2
    exit 1
fi

failed_modules=()
verified_modules=0
for module_dir in "$SET_A_DIR"/*/; do
    module_name="$(basename "$module_dir")"
    if [[ "$module_name" == "spi" ]]; then
        continue
    fi
    if [[ ! "$module_name" =~ ^(log4j|commons|snakeyaml)-p(10|[1-9])$ ]]; then
        echo "ERROR: unexpected module directory: $module_name" >&2
        exit 1
    fi
    lib_name="${BASH_REMATCH[1]}"
    pattern="${BASH_REMATCH[2]}"
    class_file="$module_dir/target/classes/seta/$lib_name/p$pattern/App.class"
    if [[ ! -f "$class_file" ]]; then
        failed_modules+=("$module_name")
    else
        verified_modules=$((verified_modules + 1))
    fi
done

if (( ${#failed_modules[@]} > 0 )); then
    echo "ERROR: these modules did not compile:" >&2
    printf '  %s\n' "${failed_modules[@]}" >&2
    exit 1
fi
if (( verified_modules != 30 )); then
    echo "ERROR: expected 30 compiled modules, found $verified_modules" >&2
    exit 1
fi
echo "Verified $verified_modules compiled application modules."

for module_dir in "$SET_A_DIR"/*/; do
    mkdir -p "$module_dir/target/sbom-jars" "$module_dir/target/runtime-jars"
done

echo "Copying dependencies for SBOM jars (includeScope=test)"
if ! "$MVN" -f "$SET_A_DIR/pom.xml" \
    org.apache.maven.plugins:maven-dependency-plugin:3.7.0:copy-dependencies \
    -DincludeScope=test \
    -DoutputDirectory=target/sbom-jars; then
    echo "ERROR: failed to copy SBOM dependency jars." >&2
    exit 1
fi

echo "Copying dependencies for runtime jars (includeScope=runtime)"
if ! "$MVN" -f "$SET_A_DIR/pom.xml" \
    org.apache.maven.plugins:maven-dependency-plugin:3.7.0:copy-dependencies \
    -DincludeScope=runtime \
    -DoutputDirectory=target/runtime-jars; then
    echo "ERROR: failed to copy runtime dependency jars." >&2
    exit 1
fi

"$PYTHON" - "$SET_A_DIR" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = root / "manifest.json"
if not manifest_path.is_file():
    raise SystemExit(f"ERROR: manifest not found: {manifest_path}")

entries = json.loads(manifest_path.read_text(encoding="utf-8"))
if len(entries) != 30:
    raise SystemExit(f"ERROR: expected 30 manifest entries, found {len(entries)}")

errors = []
seen = set()
for entry in entries:
    app_id = entry["id"]
    if app_id in seen:
        errors.append(f"duplicate manifest id: {app_id}")
    seen.add(app_id)
    app_dir = root / entry["app_dir"]
    if not app_dir.is_dir():
        errors.append(f"missing app directory: {app_dir}")
        continue
    for jar_path in entry["runtime_jars"] + entry["sbom_jars"]:
        if not (root / jar_path).is_file():
            errors.append(f"{app_id}: missing jar {jar_path}")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Verified 30 manifest entries and every listed jar.")
PY

echo "Set A build complete."
