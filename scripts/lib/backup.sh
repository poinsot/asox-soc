# shellcheck shell=bash
# Helpers shared by backup.sh and restore.sh (PROJECT.md 9.2). Source after
# lib/common.sh. Globals below are used by the scripts that source this file.
# shellcheck disable=SC2034

# Throwaway container that reads and writes volumes as root with GNU tar
# (ownership kept by number). Same pinned image as the lab agent's base.
BACKUP_IMAGE=ubuntu:noble-20260911

# Files a backup holds, relative to its directory.
MANIFEST=MANIFEST.txt
SECRETS_ENV=secrets/env
SECRETS_CERTS=secrets/certs.tar.gz

# Nodes with generated certificates in nodes/<node>/certs/ (Wazuh for core,
# MISP for intel); --with-secrets includes them.
node_has_certs() { [[ $1 == core || $1 == intel ]]; }

# "<key> <docker volume name>" for every volume of <node>, all profiles.
node_volumes() {
  compose "$1" --profile '*' config --format json | jq -r '.volumes // {} | to_entries[] | "\(.key) \(.value.name)"'
}

# Pinned image tags and versions (KEY=value) in an .env or .env.example file.
pinned_versions() {
  grep -E '^[A-Z0-9_]+(_IMAGE|_VERSION)=' "$1" | sort
}

# Lines of section "## <name>" of a manifest (up to the next section).
manifest_section() {
  awk -v s="## $2" '$0 == s { on = 1; next } /^## / { on = 0 } on && NF' "$1"
}

# Value of "<key>: value" in a manifest's header.
manifest_get() {
  sed -n "s/^$2: //p" "$1" | head -n 1
}

# Run a command in the backup container as root, with extra docker args.
backup_run() {
  local -a dargs=()
  while [[ $1 != -- ]]; do dargs+=("$1"); shift; done
  shift
  docker run --rm --network none "${dargs[@]}" "$BACKUP_IMAGE" "$@"
}
