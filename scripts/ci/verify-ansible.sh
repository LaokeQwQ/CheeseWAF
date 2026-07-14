#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ansible_root="${repo_root}/deploy/ansible"

if [[ ! -d "$ansible_root" ]]; then
  echo "No deploy/ansible directory; nothing to syntax-check."
  exit 0
fi

mapfile -d '' playbooks < <(
  find "$ansible_root" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 |
    while IFS= read -r -d '' file; do
      if grep -Eq '^[[:space:]]*-[[:space:]]*hosts:' "$file"; then
        printf '%s\0' "$file"
      fi
    done
)

if [[ "${#playbooks[@]}" -eq 0 ]]; then
  echo "No static Ansible playbooks found; generated Ansible remains covered by Go tests."
  exit 0
fi

command -v ansible-playbook >/dev/null 2>&1 || {
  echo "::error::ansible-playbook is required when static playbooks are present"
  exit 1
}

for playbook in "${playbooks[@]}"; do
  ansible-playbook --syntax-check -i 'localhost,' "$playbook"
done
