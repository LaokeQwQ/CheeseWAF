#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

fail() {
  echo "::error::$*" >&2
  exit 1
}

command -v ruby >/dev/null 2>&1 || fail "Ruby is required to parse Forgejo workflow YAML"

shopt -s nullglob
workflow_files=(.forgejo/workflows/*.yml .forgejo/workflows/*.yaml)
(( ${#workflow_files[@]} > 0 )) || fail "no Forgejo workflow files found"

ruby - "${workflow_files[@]}" <<'RUBY'
require "yaml"

ARGV.each do |path|
  begin
    YAML.parse_file(path)
  rescue Psych::SyntaxError => e
    warn "::error::invalid YAML in #{path}: #{e.message}"
    exit 1
  end
end
RUBY

for workflow in "${workflow_files[@]}"; do
  [[ -r "$workflow" ]] || fail "missing Forgejo workflow: ${workflow}"
  grep -Eq '^("?on"?):[[:space:]]*$' "$workflow" ||
    fail "${workflow} must define an on trigger block"
  grep -Eq '^jobs:[[:space:]]*$' "$workflow" ||
    fail "${workflow} must define a jobs block"

  while IFS= read -r action_ref; do
    [[ -n "$action_ref" ]] || continue
    [[ "$action_ref" =~ ^https://data\.forgejo\.org/[^@[:space:]]+@[0-9a-f]{40}$ ]] ||
      fail "${workflow} has an unpinned or non-Forgejo action reference: ${action_ref}"
  done < <(sed -nE 's/^[[:space:]]*uses:[[:space:]]*([^[:space:]#]+).*$/\1/p' "$workflow")
done

if grep -nE 'run-actionlint\.sh[^\n]*\.forgejo/workflows' .forgejo/workflows/*.yml .forgejo/workflows/*.yaml 2>/dev/null; then
  fail "Forgejo workflows must not pass Forgejo URLs to actionlint"
fi

echo "Forgejo workflow YAML and action-reference checks passed."
