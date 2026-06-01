#!/bin/bash
# Logging, SSH helpers, cloud config parsing, PID/host/IP tracking, and URL utilities.
# Sourced by deploy.sh; references SCRIPT_DIR, LOG_DIR, SSH_KEY, SSH_REMOTE_USER,
# CLOUD_CONFIG, and PIDS from the calling shell.

log()  { echo -e "${GREEN}[deploy]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[deploy]${NC} $1" >&2; }
err()  { echo -e "${RED}[deploy]${NC} $1" >&2; exit 1; }

# ----------------------------------------------------------
# Cloud config helpers (python3 for JSON parsing)
# ----------------------------------------------------------
validate_cloud_config() {
    local error
    if ! error=$(python3 -c '
import json, sys

REQUIRED = ["repoUrl", "type", "provider", "region", "authKey"]
VALID_TYPES = {"rails", "node", "wasm", "nextjs"}
VALID_PROVIDERS = {"aws", "azure", "gcp", "oci"}

try:
    with open(sys.argv[1], encoding="utf-8-sig") as f:
        data = json.load(f)
except json.JSONDecodeError as e:
    print("Invalid JSON: " + str(e))
    sys.exit(1)

for pid, cfg in data.items():
    for field in REQUIRED:
        if field not in cfg:
            print("Project " + repr(pid) + " is missing required field: " + repr(field))
            sys.exit(1)
    t = cfg["type"]
    if t not in VALID_TYPES:
        print("Project " + repr(pid) + " has invalid type " + repr(t) +
              ". Valid types: " + str(sorted(VALID_TYPES)))
        sys.exit(1)
    p = cfg["provider"]
    if p not in VALID_PROVIDERS:
        print("Project " + repr(pid) + " has invalid provider " + repr(p) +
              ". Valid providers: " + str(sorted(VALID_PROVIDERS)))
        sys.exit(1)
' "$CLOUD_CONFIG" 2>&1); then
        err "cloud.json validation failed: $error"
    fi
}

cloud_get() {
    local id="$1" field="$2"
    if [ -z "$CLOUD_CONFIG" ] || [ ! -f "$CLOUD_CONFIG" ]; then
        echo ""
        return
    fi
    python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8-sig") as f:
    data = json.load(f)
value = data.get(sys.argv[2], {}).get(sys.argv[3], "")
print("" if value is None else value)
' "$CLOUD_CONFIG" "$id" "$field" 2>/dev/null || echo ""
}

cloud_ids() {
    if [ -z "$CLOUD_CONFIG" ] || [ ! -f "$CLOUD_CONFIG" ]; then
        echo ""
        return
    fi
    python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8-sig") as f:
    print(" ".join(json.load(f).keys()))
' "$CLOUD_CONFIG" 2>/dev/null || echo ""
}

is_cloud() { [ -n "$(cloud_get "$1" provider)" ]; }

resolve_cloud_path() {
    local raw_path="$1"
    local resolved="$raw_path"
    [[ "$resolved" = /* ]] || resolved="$(dirname "$CLOUD_CONFIG")/$resolved"
    [ -f "$resolved" ] || err "Auth file not found: $resolved"
    realpath "$resolved"
}

env_key_for_id() {
    echo "$(echo "$1" | tr '[:lower:]' '[:upper:]' | tr '-' '_')_URL"
}

write_env_url() {
    local id="$1" url="$2"
    local env_key env_file
    env_key="$(env_key_for_id "$id")"
    env_file="$SCRIPT_DIR/.env.local"
    touch "$env_file"
    sed -i '' "/^${env_key}=/d" "$env_file"
    echo "${env_key}=${url}" >> "$env_file"
}

# ----------------------------------------------------------
# PID / host / IP / user tracking (for local processes and refresh)
# ----------------------------------------------------------
save_pid()  { echo "$1" > "$LOG_DIR/$2.pid"; }
read_pid()  { cat "$LOG_DIR/$1.pid" 2>/dev/null || echo ""; }
save_host() { echo "$1" > "$LOG_DIR/$2.host"; }
read_host() { cat "$LOG_DIR/$1.host" 2>/dev/null || echo ""; }
save_ip()   { echo "$1" > "$LOG_DIR/$2.ip"; }
read_ip()   { cat "$LOG_DIR/$1.ip"   2>/dev/null || echo ""; }
save_user() { echo "$1" > "$LOG_DIR/$2.user"; }
read_user() { cat "$LOG_DIR/$1.user" 2>/dev/null || echo "ubuntu"; }

kill_project() {
    local id="$1"
    local pid
    pid="$(read_pid "$id")"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null && log "Stopped $id (pid $pid)" || true
    fi
    rm -f "$LOG_DIR/$id.pid"
}

cleanup() {
    local status=$?
    trap - EXIT
    if [ ${#PIDS[@]} -gt 0 ]; then
        echo ""
        log "Shutting down local services..."
        for pid in "${PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
    fi
    exit "$status"
}

on_signal() { exit 130; }

# ----------------------------------------------------------
# SSH key (shared across all cloud providers)
# ----------------------------------------------------------
ensure_ssh_key() {
    if [ ! -f "$SSH_KEY" ]; then
        log "Generating deploy SSH key at $SSH_KEY..."
        ssh-keygen -t rsa -b 4096 -f "$SSH_KEY" -N "" -C "portfolio-deploy" -q
    fi
}

ssh_to() {
    local ip="$1"; shift
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=30 "${SSH_REMOTE_USER}@$ip" "$@"
}

wait_for_ssh() {
    local host="$1"
    local max=120 waited=0
    log "Waiting for SSH on $host..."
    until ssh_to "$host" "exit" 2>/dev/null; do
        sleep 5; waited=$((waited + 5))
        [ $waited -ge $max ] && err "Timed out waiting for SSH on $host after ${max}s"
        log "  still waiting... (${waited}s)"
    done
    log "SSH ready on $host"
}

scp_to() {
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$@"
}

# ----------------------------------------------------------
# Parse a GitHub URL into: clone_url  branch  subdir
#   https://github.com/user/repo/tree/main/subdir -> "https://github.com/user/repo main subdir"
#   https://github.com/user/repo                  -> "https://github.com/user/repo main "
# ----------------------------------------------------------
parse_repo_url() {
    local url="${1%.git}"
    if echo "$url" | grep -q "/tree/"; then
        local base="${url%%/tree/*}"
        local rest="${url#*/tree/}"
        local branch="${rest%%/*}"
        local subdir="${rest#*/}"
        [ "$subdir" = "$branch" ] && subdir=""
        echo "$base $branch $subdir"
    else
        echo "$url main "
    fi
}

# ----------------------------------------------------------
# Return the Content-Type for a file path (used for object storage uploads)
# ----------------------------------------------------------
get_mime_type() {
    case "${1##*.}" in
        html)         echo "text/html" ;;
        js|mjs)       echo "application/javascript" ;;
        wasm)         echo "application/wasm" ;;
        css)          echo "text/css" ;;
        json)         echo "application/json" ;;
        png)          echo "image/png" ;;
        jpg|jpeg)     echo "image/jpeg" ;;
        gif)          echo "image/gif" ;;
        svg)          echo "image/svg+xml" ;;
        ico)          echo "image/x-icon" ;;
        txt)          echo "text/plain" ;;
        *)            echo "application/octet-stream" ;;
    esac
}
