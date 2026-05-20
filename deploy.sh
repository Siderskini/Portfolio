#!/bin/bash
set -e

# ============================================================
# Portfolio Deploy Script
#
# Usage:
#   ./deploy.sh                          Full local deploy
#   ./deploy.sh --cloud cloud.json       Deploy per cloud config (local fallback for unlisted projects)
#   ./deploy.sh --refresh <id>           Refresh one project (local or cloud)
#   ./deploy.sh --cloud cloud.json --refresh <id>
#
# cloud.json format: see cloud.json.template
# Helper scripts live in scripts/
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECTS_DIR="$SCRIPT_DIR/projects"
LOG_DIR="$SCRIPT_DIR/logs"
SSH_KEY="$HOME/.ssh/portfolio_deploy"
SSH_REMOTE_USER="ubuntu"
CLOUD_CONFIG=""
REFRESH_ID=""
USE_VM=false        # set to true via --vm to force VM hosting for wasm projects
PIDS=()

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

# Source helper scripts
source "$SCRIPT_DIR/scripts/common.sh"
source "$SCRIPT_DIR/scripts/providers.sh"
source "$SCRIPT_DIR/scripts/storage.sh"
source "$SCRIPT_DIR/scripts/cloud_deploy.sh"
source "$SCRIPT_DIR/scripts/local_deploy.sh"

# ----------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------
usage() {
    cat <<EOF
Usage:
  ./deploy.sh
  ./deploy.sh --cloud cloud.json
  ./deploy.sh --refresh <id>
  ./deploy.sh --cloud cloud.json --refresh <id>
  ./deploy.sh --cloud cloud.json --vm          # force VM hosting for wasm (instead of object storage)

Flags:
  --cloud <file>    Path to cloud config JSON
  --refresh <id>    Refresh a single project (git pull + redeploy)
  --vm              Opt-in: host wasm projects on a VM instead of object storage
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cloud)
            [ $# -ge 2 ] || err "--cloud requires a file path"
            [ -f "$2" ] || err "Cloud config file not found: $2"
            CLOUD_CONFIG="$(realpath "$2")"
            shift 2
            ;;
        --refresh)
            [ $# -ge 2 ] || err "--refresh requires a project id"
            REFRESH_ID="$2"
            shift 2
            ;;
        --vm)
            USE_VM=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)  err "Unknown argument: $1" ;;
    esac
done

mkdir -p "$PROJECTS_DIR" "$LOG_DIR"

if ! command -v ansible-playbook &>/dev/null; then
    warn "ansible-playbook not found — cloud VM deploys will fail. Install: pip install ansible && ansible-galaxy collection install -r ansible/requirements.yml"
fi

trap on_signal SIGINT SIGTERM
trap cleanup EXIT

# ----------------------------------------------------------
# --refresh <id> entry point
# ----------------------------------------------------------
if [ -n "$REFRESH_ID" ]; then
    if is_cloud "$REFRESH_ID"; then
        refresh_cloud_project "$REFRESH_ID"
        # Sync updated URLs to portfolio VM
        sync_urls_to_portfolio_vm
    else
        refresh_local_project "$REFRESH_ID"
    fi
    exit 0
fi

# ----------------------------------------------------------
# Full deploy
# ----------------------------------------------------------
for id in flowers labyrinth fishing; do
    if is_cloud "$id"; then
        deploy_cloud_project "$id"
    else
        case "$id" in
            flowers)   start_flowers_local ;;
            labyrinth) start_labyrinth_local ;;
            fishing)   start_fishing_local ;;
        esac
    fi
done

if is_cloud "portfolio"; then
    deploy_cloud_project "portfolio"
else
    start_portfolio_local
fi

# Push updated project URLs to cloud portfolio VM so links reflect real deployments
is_cloud "portfolio" && sync_urls_to_portfolio_vm

sleep 3

echo ""
log "============================================"
log "  All services running!"
log "============================================"
for id in flowers labyrinth fishing portfolio; do
    host="$(read_host "$id")"
    log "  $(printf '%-12s' "$id") $host"
done
log "============================================"
log "  ./deploy.sh --refresh <id>   Refresh one project"
log "  Ctrl+C to stop all local services"
log "============================================"
echo ""

wait
