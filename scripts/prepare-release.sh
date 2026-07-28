#!/usr/bin/env bash

# SPDX-FileCopyrightText: Chirag Rao <crao@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

# How to run (example):
# ./scripts/prepare-release.sh 0.2.1

# Steps followed:
# 1. Validate passed params.
# 2. Update [package] version in all related Cargo.toml files in our owned workspaces.
# 3. Update CSV template with new version.
# 4. Update README with new version.
# 5. Refresh Cargo.lock for workspace package versions.

set -euo pipefail

DRY_RUN=false
VERSION=""


function usage() {
    echo "Usage: $0 [--dry-run] <VERSION>"
    echo "  VERSION must be bare semver (e.g. 0.2.1), without a leading 'v'."
    exit 1;
}

# Validate passed params.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; usage ;;
        *) VERSION="$1"; shift ;;
    esac
done

# Print usage and exit if VERSION is not set.
[[ -z "$VERSION" ]] && usage

# Reject a leading 'v' — image tags add it later.
if [[ "$VERSION" == v* ]]; then
    echo "ERROR: VERSION must not start with 'v'. Got: $VERSION"
    exit 1
fi

# Require MAJOR.MINOR.PATCH (semver).
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: VERSION must match MAJOR.MINOR.PATCH. Got: $VERSION"
    exit 1
fi

# Get the project root directory.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Gets only local workspace packages, not dependencies. 
mapfile -t CRATES < <(
    cargo metadata --no-deps --format-version=1 \
        | jq -r --arg root "$PROJECT_ROOT/" \
            '.packages[] | select(.source == null) | .manifest_path | sub($root; "")'
)

if [[ ${#CRATES[@]} -eq 0 ]]; then
    echo "ERROR: no workspace member Cargo.toml files found via cargo metadata" >&2
    exit 1
fi

# Validate that VERSION is a valid semver increment of the current version.
CURRENT_VERSION=$(cargo metadata --no-deps --format-version=1 | jq -r '.packages[] | select(.source == null) | .version' | head -1)
if [[ -n "$CURRENT_VERSION" ]]; then
    # Splits the current version into major, minor, and patch components.
    IFS='.' read -r CUR_MAJOR CUR_MINOR CUR_PATCH <<< "$CURRENT_VERSION"
    # Splits the new version into major, minor, and patch components.
    IFS='.' read -r NEW_MAJOR NEW_MINOR NEW_PATCH <<< "$VERSION"

    # List of valid next versions.
    VALID_NEXT=(
        "$((CUR_MAJOR+1)).0.0"
        "$CUR_MAJOR.$((CUR_MINOR+1)).0"
        "$CUR_MAJOR.$CUR_MINOR.$((CUR_PATCH+1))"
    )

    # Check if the new version is a valid increment of the current version.
    valid=false
    for v in "${VALID_NEXT[@]}"; do
        [[ "$v" == "$VERSION" ]] && valid=true && break
    done

    if ! $valid; then
        echo "ERROR: $VERSION is not a valid increment of $CURRENT_VERSION."
        echo "  Valid next versions: ${VALID_NEXT[*]}"
        exit 1
    fi
fi

CSV="bundle/static/manifests/trusted-cluster-operator.clusterserviceversion.yaml"
README="README.md"

# Dry Run Summary (skips and returns early, so that actual execution is not performed).
if $DRY_RUN; then
    echo "============================================"
    echo "  DRY RUN: prepare-release $VERSION"
    echo "============================================"
    echo ""
    echo "Target version: $VERSION (tag: v$VERSION)"
    echo ""

    echo "--- Cargo.toml [package] version bumps ---"
    for file in "${CRATES[@]}"; do
        if [[ ! -f "$file" ]]; then
            echo "  WARN: $file not found, would skip"
            continue
        fi
        current=$(sed -n '/^\[package\]/,/^\[/{s/^version = "\(.*\)"/\1/p}' "$file")
        if [[ "$current" == "$VERSION" ]]; then
            echo "  $file: $current (already at target)"
        else
            echo "  $file: $current -> $VERSION"
        fi
    done
    echo ""

    echo "--- CSV: $CSV ---"
    if [[ -f "$CSV" ]]; then
        csv_name=$(grep -m1 '^  name: trusted-cluster-operator\.' "$CSV" | sed 's/.*trusted-cluster-operator\.//')
        csv_ver=$(grep -m1 '^  version:' "$CSV" | awk '{print $2}')
        csv_img=$(grep -m1 'containerImage:' "$CSV" | sed 's/.*trusted-cluster-operator://' | tr -d '"')

        echo "  metadata.name: trusted-cluster-operator.$csv_name -> trusted-cluster-operator.v$VERSION"
        echo "  spec.version:  $csv_ver -> $VERSION"
        echo "  containerImage tag: $csv_img -> v$VERSION"
        echo ""
        echo "  TEC image tags bumped to v$VERSION:"
        for img in trusted-cluster-operator compute-pcrs registration-server attestation-key-register; do
            current_tag=$(grep -m1 "quay.io/trusted-execution-clusters/$img:" "$CSV" \
                | sed "s|.*$img:||" | tr -d ' ",' )
            echo "    quay.io/trusted-execution-clusters/$img: $current_tag -> v$VERSION"
        done
        echo ""
        echo "  NOT bumped (external):"
        grep "quay.io/trusted-execution-clusters/key-broker-service:" "$CSV" \
            | head -1 | sed 's/.*key-broker-service://' | tr -d ' ",' \
            | xargs -I{} echo "    quay.io/trusted-execution-clusters/key-broker-service:{} (unchanged)"
    else
        echo "  WARN: $CSV not found"
    fi
    echo ""

    echo "--- README: $README ---"
    if [[ -f "$README" ]]; then
        current_tag=$(grep -m1 '^export TAG=' "$README" | sed 's/export TAG=//')
        echo "  export TAG=$current_tag -> export TAG=v$VERSION"
    else
        echo "  WARN: $README not found"
    fi
    echo ""

    echo "--- Cargo.lock ---"
    echo "  Would run: cargo metadata --format-version=1 (syncs Cargo.lock without upgrading deps)"
    echo ""
    echo "============================================"
    echo "  No files were modified (dry run)."
    echo "============================================"
    exit 0
fi

# --- Actual execution ---

echo "=> Updating [package] version (crate own version only) to $VERSION ..."
for file in "${CRATES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "WARN: $file not found, skipping"
        continue
    fi
    # Only rewrite version under [package]; stop at the next [section].
    sed -i '/^\[package\]/,/^\[/{s/^version = ".*"/version = "'"$VERSION"'"/}' "$file"
done

echo "=> Updating CSV template: $CSV ..."
# Update metadata.name
sed -i 's/^\(  name: trusted-cluster-operator\.\)v[0-9]\+\.[0-9]\+\.[0-9]\+/\1v'"$VERSION"'/' "$CSV"
# Update spec.version
sed -i 's/^\(  version: \)[0-9]\+\.[0-9]\+\.[0-9]\+/\1'"$VERSION"'/' "$CSV"
# Update containerImage annotation (TEC operator image)
sed -i 's|\(containerImage: "quay.io/trusted-execution-clusters/trusted-cluster-operator:\)[^"]*|\1v'"$VERSION"'|' "$CSV"
# Update TEC component image tags (but NOT trustee/key-broker-service)
sed -i \
    -e 's|\(quay.io/trusted-execution-clusters/trusted-cluster-operator:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
    -e 's|\(quay.io/trusted-execution-clusters/compute-pcrs:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
    -e 's|\(quay.io/trusted-execution-clusters/registration-server:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
    -e 's|\(quay.io/trusted-execution-clusters/attestation-key-register:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
    "$CSV"

echo "=> Updating $README ..."
sed -i 's/^\(export TAG=\).*/\1v'"$VERSION"'/' "$README"
# Bump the version in the TAG note of the README.
sed -i '/TAG.*semantic version/s/\(e\.g\., `\)[^`]*/\1v'"$VERSION"'/' "$README"

echo "=> Refreshing Cargo.lock for workspace package versions ..."
cargo metadata --format-version=1 >/dev/null

echo ""
echo "=== prepare-release $VERSION complete ==="
echo "Files updated:"
for file in "${CRATES[@]}"; do
    echo "  - $file"
done
echo "  - $CSV"
echo "  - $README"
echo "  - Cargo.lock"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Stage and commit: git add -A && git commit -m 'Release $VERSION'"
echo "  3. Create a PR against the branch you want to release from (e.g. main)"
echo "  4. After the PR is merged, checkout the target branch and tag (only a maintainer can do this):"
echo "       git checkout <target branch> && git pull origin <target branch>"
echo "       git tag $VERSION && git push origin $VERSION"
