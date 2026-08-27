#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
manifest="${TAILSTATE_INVARIANT_MANIFEST:-$repo_dir/.github/invariant-tests.txt}"

if [[ ! -f "$manifest" ]]; then
    echo "invariant manifest not found: $manifest" >&2
    exit 1
fi

declare -a invariant_names=()
declare -a invariant_lines=()
declare -A seen=()
line_number=0
while IFS= read -r entry || [[ -n "$entry" ]]; do
    ((line_number += 1))
    if [[ "$entry" == *$'\r' ]]; then
        entry="${entry%$'\r'}"
    fi
    if [[ -z "$entry" || "$entry" == \#* ]]; then
        continue
    fi
    if [[ ! "$entry" =~ ^Test[A-Za-z0-9_]+$ ]]; then
        echo "invalid invariant name at $manifest:$line_number: $entry" >&2
        exit 1
    fi
    if [[ -n "${seen[$entry]+present}" ]]; then
        echo "duplicate invariant name at $manifest:$line_number: $entry" >&2
        exit 1
    fi
    seen["$entry"]=1
    invariant_names+=("$entry")
    invariant_lines+=("$line_number")
done < "$manifest"

if [[ ${#invariant_names[@]} -eq 0 ]]; then
    echo "invariant manifest is empty: $manifest" >&2
    exit 1
fi

# Names are restricted to Go test identifiers above, so this alternation
# cannot inject regular-expression operators or shell syntax. Keep the
# expansion quoted when passing it to `go test` below.
invariant_regex='^('
for invariant_name in "${invariant_names[@]}"; do
    invariant_regex+="$invariant_name|"
done
invariant_regex="${invariant_regex%|})$"

log_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p "$log_dir"
invariant_log="$(mktemp "$log_dir/tailstate-invariant-tests.XXXXXX.log")"
trap 'rm -f "$invariant_log"' EXIT

set +e
go test -race -count=1 -v -run "$invariant_regex" ./... | tee "$invariant_log"
test_status=${PIPESTATUS[0]}
set -e

validation_status=0
for index in "${!invariant_names[@]}"; do
    invariant_name="${invariant_names[$index]}"
    declaration="$manifest:${invariant_lines[$index]}"
    if grep -Fq -- "--- FAIL: $invariant_name (" "$invariant_log"; then
        echo "invariant test failed: $invariant_name (declared at $declaration)" >&2
        validation_status=1
    elif ! grep -Fq -- "--- PASS: $invariant_name (" "$invariant_log"; then
        echo "invariant test did not run or pass: $invariant_name (declared at $declaration)" >&2
        validation_status=1
    fi
done

if [[ $test_status -ne 0 ]]; then
    if [[ $validation_status -eq 0 ]]; then
        echo "invariant test command failed (manifest: $manifest)" >&2
    fi
    exit "$test_status"
fi
exit "$validation_status"
