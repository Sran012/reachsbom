#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/env.sh"
cd "$ROOT/java-analyzer"
mvn -q -DskipTests package
echo "built $ROOT/java-analyzer/target/reachsbom-analyzer.jar"
