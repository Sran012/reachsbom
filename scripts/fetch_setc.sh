#!/usr/bin/env bash
# Clone the Set C Spring Guides repositories (shallow, depth 1).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPOS="$ROOT/benchmarks/setC/repos"
mkdir -p "$REPOS"

repos=(
    "gs-spring-boot|https://github.com/spring-guides/gs-spring-boot.git"
    "gs-rest-service|https://github.com/spring-guides/gs-rest-service.git"
    "gs-maven|https://github.com/spring-guides/gs-maven.git"
    "gs-scheduling-tasks|https://github.com/spring-guides/gs-scheduling-tasks.git"
    "gs-consuming-rest|https://github.com/spring-guides/gs-consuming-rest.git"
)

for entry in "${repos[@]}"; do
    name="${entry%%|*}"
    url="${entry#*|}"
    destination="$REPOS/$name"
    if [[ -d "$destination/.git" ]]; then
        printf '[skip] %s already cloned at %s\n' "$name" "$destination"
        continue
    fi
    rm -rf "$destination"
    printf '[clone] %s\n  %s\n' "$name" "$url"
    git clone --depth 1 "$url" "$destination"
done

printf '\nCloned repositories:\n'
for entry in "${repos[@]}"; do
    name="${entry%%|*}"
    printf '  %s\n' "$REPOS/$name"
done
