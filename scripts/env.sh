#!/usr/bin/env bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="$ROOT/.tools/jdk17"
export PATH="$JAVA_HOME/bin:$ROOT/.tools/maven/bin:$ROOT/.tools/bin:$PATH"
