#!/usr/bin/env bash
# Generate the per-machine security material of a node (git-ignored).
#   core : into nodes/core/certs/, using the pinned Wazuh images:
#          - Wazuh certificates (root CA, indexer, manager/Filebeat, admin),
#            via the official wazuh-certs-generator and
#            nodes/core/wazuh/config/certs.yml;
#          - the indexer's internal_users.yml, with the bcrypt hash of
#            INDEXER_ADMIN_PASSWORD from nodes/core/.env.
#   intel: into nodes/intel/certs/, a self-signed certificate for misp-nginx
#          (MISP's HTTPS front end; clients skip verification, PROJECT.md 4.1).
# Idempotent: existing files are kept unless --force is given.
#
# Usage: scripts/gen-certs.sh [--force] [core|intel]   (default: core)
set -euo pipefail
# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

FORCE=0 NODE=core
for arg in "$@"; do
  case $arg in
    --force) FORCE=1 ;;
    core|intel) NODE=$arg ;;
    -h|--help) print_usage "$0"; exit 0 ;;
    *) die "unknown argument: $arg" ;;
  esac
done

# ---------------------------------------------------------------- intel ---

# misp-nginx serves HTTPS only when /etc/nginx/certs/{cert,key}.pem exist.
# Generated with the misp-nginx image's openssl, owned by its nginx user.
gen_misp_cert() {
  local dir env image base host san
  dir="$(node_dir intel)/certs"
  env="$(node_dir intel)/.env"
  [[ -f $env ]] || die "nodes/intel/.env not found; run scripts/render-env.sh first"
  if (( ! FORCE )) && [[ -f $dir/cert.pem && -f $dir/key.pem ]]; then
    skip "MISP certificate already exists (use --force to regenerate)"
    return 0
  fi
  image=$(env_get "$env" MISP_NGINX_IMAGE)
  base=$(env_get "$env" MISP_BASE_URL)
  host=${base#https://}; host=${host%%[:/]*}
  # Names clients may use: the soc-net alias, this machine, the base URL host.
  san="DNS:misp-nginx,DNS:localhost,IP:127.0.0.1"
  if [[ $host =~ ^[0-9.]+$ ]]; then san+=",IP:$host"; elif [[ $host != localhost ]]; then san+=",DNS:$host"; fi
  mkdir -p "$dir"
  docker run --rm --user 0 -v "$dir:/out" --entrypoint sh "$image" -c '
    set -e
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1095 \
      -subj "/O=ASOX SOC/CN=misp-nginx" -addext "subjectAltName=$1" \
      -keyout /out/key.pem -out /out/cert.pem 2>/dev/null
    chown 101:101 /out/key.pem /out/cert.pem
    chmod 400 /out/key.pem
    chmod 644 /out/cert.pem
  ' _ "$san"
  pass "MISP certificate written to nodes/intel/certs/ ($san)"
}

if [[ $NODE == intel ]]; then
  gen_misp_cert
  exit 0
fi

# ----------------------------------------------------------------- core ---

CORE=$(node_dir core)
CERTS="$CORE/certs"
ENV_FILE="$CORE/.env"
[[ -f $ENV_FILE ]] || die "nodes/core/.env not found; run scripts/render-env.sh first"
GEN_IMAGE=$(env_get "$ENV_FILE" WAZUH_CERTS_GENERATOR_IMAGE)
INDEXER_IMAGE=$(env_get "$ENV_FILE" WAZUH_INDEXER_IMAGE)
[[ -n $GEN_IMAGE && -n $INDEXER_IMAGE ]] || die "image variables missing in nodes/core/.env; re-run scripts/render-env.sh"

# Wazuh 4.14 certificate tool, matching the pinned images.
CERT_TOOL_VERSION=4.14
# Indexer runs as uid 1000; keys are readable only by it (and root).
INDEXER_UID=1000

CERT_FILES=(root-ca.pem root-ca.key admin.pem admin-key.pem
  wazuh-indexer.pem wazuh-indexer-key.pem wazuh-manager.pem wazuh-manager-key.pem)

certs_present() {
  local f
  for f in "${CERT_FILES[@]}"; do [[ -f $CERTS/$f ]] || return 1; done
}

gen_certificates() {
  info "generating Wazuh certificates with $GEN_IMAGE"
  mkdir -p "$CERTS"
  # The generator writes to its own /certificates (it chmods that tree);
  # the files are then copied to the mounted output with our permissions.
  docker run --rm \
    -e CERT_TOOL_VERSION="$CERT_TOOL_VERSION" \
    -v "$CORE/wazuh/config/certs.yml:/config/certs.yml:ro" \
    -v "$CERTS:/out" \
    --entrypoint bash "$GEN_IMAGE" -c '
      set -e
      mkdir -p /certificates
      /entrypoint.sh >/tmp/generator.log 2>&1 || { cat /tmp/generator.log; exit 1; }
      for f in "$@"; do
        test -f "/certificates/$f" || { echo "missing $f"; cat /tmp/generator.log; exit 1; }
        cp "/certificates/$f" "/out/$f"
        case "$f" in
          *.key|*-key.pem) chmod 400 "/out/$f" ;;
          *) chmod 644 "/out/$f" ;;
        esac
        chown '"$INDEXER_UID:$INDEXER_UID"' "/out/$f"
      done
    ' _ "${CERT_FILES[@]}"
  pass "certificates written to nodes/core/certs/"
}

gen_internal_users() {
  local password hash
  password=$(env_get "$ENV_FILE" INDEXER_ADMIN_PASSWORD)
  [[ -n $password ]] || die "INDEXER_ADMIN_PASSWORD missing in nodes/core/.env"
  info "hashing the indexer admin password with $INDEXER_IMAGE"
  hash=$(docker run --rm -e PW="$password" --entrypoint bash "$INDEXER_IMAGE" -c \
    'JAVA_HOME=/usr/share/wazuh-indexer/jdk bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$PW"' \
    2>/dev/null | grep -E '^[$]2[aby][$]' | tail -n 1)
  [[ -n $hash ]] || die "could not hash the indexer admin password"
  local tmp
  tmp=$(mktemp "$CERTS/.internal_users.XXXXXX")
  cat > "$tmp" <<EOF
# GENERATED by scripts/gen-certs.sh; do not commit.
# Loaded into the indexer's security index on first start only.
# Other users (e.g. grafana-ro) are created by bootstrap.sh through the API.
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$hash"
  reserved: true
  backend_roles:
  - "admin"
  description: "Indexer admin"
EOF
  chmod 644 "$tmp"
  mv "$tmp" "$CERTS/internal_users.yml"
  pass "indexer internal_users.yml written to nodes/core/certs/"
}

if (( FORCE )) || ! certs_present; then
  gen_certificates
else
  skip "certificates already exist (use --force to regenerate)"
fi

if (( FORCE )) || [[ ! -f $CERTS/internal_users.yml ]]; then
  gen_internal_users
else
  skip "internal_users.yml already exists (use --force to regenerate)"
fi
