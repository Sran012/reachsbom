#!/usr/bin/env bash
# Fetch and inventory the Set B real world artifacts.
#
# Downloads (into benchmarks/setB/downloads, gitignored):
#   - Apache Solr 8.11.0
#   - Ghidra 10.0.4
#
# Then scans each extracted directory with Syft and writes JSON SBOMs into
# results/raw. A failed download is recorded with its URL and error instead of
# being replaced by a fabricated artifact.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOADS="$ROOT/benchmarks/setB/downloads"
RAW="$ROOT/results/raw"
ERROR_LOG="$DOWNLOADS/download-errors.log"
mkdir -p "$DOWNLOADS" "$RAW"

SYFT="${SYFT:-$ROOT/.tools/bin/syft}"
if ! command -v "$SYFT" >/dev/null 2>&1; then
    SYFT="$(command -v syft || true)"
fi

record_error() {
    local url="$1"
    local message="$2"
    printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$url" "$message" >> "$ERROR_LOG"
    printf 'ERROR: %s\n  URL: %s\n  %s\n' "$url" "$url" "$message" >&2
}

download() {
    local url="$1"
    local archive="$2"
    local label="$3"

    if [[ -s "$archive" ]]; then
        printf '[skip] %s already downloaded: %s\n' "$label" "$archive"
        return 0
    fi

    printf '[download] %s\n  %s\n' "$label" "$url"
    local output
    if output="$(curl -fL --retry 3 --retry-delay 5 --connect-timeout 30 \
        --max-time 7200 -o "$archive.part" "$url" 2>&1)"; then
        mv "$archive.part" "$archive"
        printf '[ok] %s -> %s\n' "$label" "$archive"
        return 0
    fi
    rm -f "$archive.part"
    record_error "$url" "download failed: $output"
    return 1
}

extract_tar() {
    local archive="$1"
    local label="$2"
    local output
    if output="$(tar -xzf "$archive" -C "$DOWNLOADS" 2>&1)"; then
        printf '[ok] extracted %s\n' "$label"
        return 0
    fi
    record_error "$archive" "tar extraction failed: $output"
    return 1
}

extract_zip() {
    local archive="$1"
    local label="$2"
    local output
    if output="$(unzip -q -o "$archive" -d "$DOWNLOADS" 2>&1)"; then
        printf '[ok] extracted %s\n' "$label"
        return 0
    fi
    record_error "$archive" "zip extraction failed: $output"
    return 1
}

scan_with_syft() {
    local directory="$1"
    local output_file="$2"
    local label="$3"

    if [[ ! -d "$directory" ]]; then
        record_error "$directory" "cannot scan $label: directory does not exist"
        return 1
    fi
    if [[ -z "$SYFT" || ! -x "$SYFT" ]]; then
        record_error "$directory" "cannot scan $label: syft executable not found"
        return 1
    fi

    printf '[syft] scanning %s\n' "$directory"
    local output
    if output="$("$SYFT" "dir:$directory" -o json 2>&1 > "$output_file.tmp")"; then
        mv "$output_file.tmp" "$output_file"
        printf '[ok] wrote %s\n' "$output_file"
        return 0
    fi
    rm -f "$output_file.tmp"
    record_error "$directory" "syft scan of $label failed: $output"
    return 1
}

SOLR_URL="https://archive.apache.org/dist/lucene/solr/8.11.0/solr-8.11.0.tgz"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.4_build/ghidra_10.0.4_PUBLIC_20210928.zip"

SOLR_ARCHIVE="$DOWNLOADS/solr-8.11.0.tgz"
GHIDRA_ARCHIVE="$DOWNLOADS/ghidra_10.0.4_PUBLIC_20210928.zip"
SOLR_DIR="$DOWNLOADS/solr-8.11.0"
GHIDRA_DIR="$DOWNLOADS/ghidra_10.0.4_PUBLIC"

if download "$SOLR_URL" "$SOLR_ARCHIVE" "Apache Solr 8.11.0"; then
    extract_tar "$SOLR_ARCHIVE" "Apache Solr 8.11.0"
fi

if download "$GHIDRA_URL" "$GHIDRA_ARCHIVE" "Ghidra 10.0.4"; then
    extract_zip "$GHIDRA_ARCHIVE" "Ghidra 10.0.4"
fi

if [[ -d "$SOLR_DIR" ]]; then
    scan_with_syft "$SOLR_DIR" "$RAW/setb-solr.syft.json" "Solr 8.11.0"
fi

if [[ -d "$GHIDRA_DIR" ]]; then
    scan_with_syft "$GHIDRA_DIR" "$RAW/setb-ghidra.syft.json" "Ghidra 10.0.4"
fi

# Report the log4j-core versions Syft observed. This is informational; a
# mismatch is printed but does not hide the raw SBOM output.
python3 - "$RAW/setb-solr.syft.json" "$RAW/setb-ghidra.syft.json" <<'PY'
import json
import os
import sys

expected = {
    "setb-solr.syft.json": "2.14.1",
    "setb-ghidra.syft.json": "2.12.1",
}
status = 0
for path in sys.argv[1:]:
    name = os.path.basename(path)
    if not os.path.exists(path):
        print("%s: missing" % name)
        status = 1
        continue
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    versions = sorted({
        str(artifact.get("version", ""))
        for artifact in document.get("artifacts", [])
        if str(artifact.get("name", "")).lower() == "log4j-core"
    })
    want = expected.get(name)
    print("%s: log4j-core versions = %s (expected %s)" % (name, versions or "none", want))
    if want not in versions:
        status = 1
if status:
    print("One or more expected log4j-core versions were not found.")
sys.exit(status)
PY

if [[ -f "$ERROR_LOG" ]]; then
    printf '\nDownload or scan errors were recorded in %s\n' "$ERROR_LOG"
fi
