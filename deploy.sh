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
# ============================================================

# Use the system bundler directly — avoids the broken /usr/local/bin/bundle shebang
# (which points to a non-existent ruby3.2). Do NOT strip /usr/local/bin from PATH
# as other tools (e.g. AWS CLI) live there.
BUNDLE="/usr/bin/bundle3.3"

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
log()  { echo -e "${GREEN}[deploy]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[deploy]${NC} $1" >&2; }
err()  { echo -e "${RED}[deploy]${NC} $1" >&2; exit 1; }

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
        *)          err "Unknown argument: $1" ;;
    esac
done

mkdir -p "$PROJECTS_DIR" "$LOG_DIR"

# ----------------------------------------------------------
# Cloud config helpers (python3 for JSON parsing)
# ----------------------------------------------------------
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
    sed -i "/^${env_key}=/d" "$env_file"
    echo "${env_key}=${url}" >> "$env_file"
}

# ----------------------------------------------------------
# PID / host tracking (for local processes and refresh)
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
trap on_signal SIGINT SIGTERM
trap cleanup EXIT

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
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=30 "${SSH_REMOTE_USER}@$ip" "$@"
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

# ----------------------------------------------------------
# VM setup scripts sent via SSH for each project type.
# Variables are substituted by the caller before piping to bash.
# ----------------------------------------------------------
rails_setup_script() {
    local clone_url="$1" branch="$2" subdir="$3" port="$4"
    cat <<SCRIPT
set -e
. /etc/os-release 2>/dev/null || true
case "\${ID:-}" in
  ol|rhel|centos|fedora|rocky|almalinux) IS_RPM=true ;;
  *) IS_RPM=false ;;
esac

if \$IS_RPM; then
  # Oracle Linux / RHEL: snap not available — use rbenv
  sudo dnf install -y git curl make gcc gcc-c++ libffi-devel openssl-devel readline-devel zlib-devel sqlite-devel
  [ ! -d "\$HOME/.rbenv" ] && git clone -q --depth 1 https://github.com/rbenv/rbenv.git ~/.rbenv
  [ ! -d "\$HOME/.rbenv/plugins/ruby-build" ] && \
    git clone -q --depth 1 https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build || \
    git -C "\$HOME/.rbenv/plugins/ruby-build" pull -q
  export PATH="\$HOME/.rbenv/bin:\$PATH"
  eval "\$(rbenv init -)"
  rbenv install 3.2.3 --skip-existing
  rbenv global 3.2.3
else
  # Ubuntu: prefer snap (precompiled, ~30s) — fall back to rbenv if snapd unavailable
  sudo apt-get update -qq
  sudo apt-get install -y -qq git curl libsqlite3-dev
  if ! /snap/bin/ruby --version 2>/dev/null | grep -q "ruby 3\.2"; then
    if command -v snap &>/dev/null && sudo snap wait system seed.loaded 2>/dev/null; then
      sudo snap install ruby --classic --channel=3.2/stable
      export PATH="/snap/bin:\$PATH"
    else
      sudo apt-get install -y -qq libssl-dev zlib1g-dev libyaml-dev
      [ ! -d "\$HOME/.rbenv" ] && git clone -q --depth 1 https://github.com/rbenv/rbenv.git ~/.rbenv
      [ ! -d "\$HOME/.rbenv/plugins/ruby-build" ] && \
        git clone -q --depth 1 https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build || \
        git -C "\$HOME/.rbenv/plugins/ruby-build" pull -q
      export PATH="\$HOME/.rbenv/bin:\$PATH"
      eval "\$(rbenv init -)"
      rbenv install 3.2.3 --skip-existing
      rbenv global 3.2.3
    fi
  else
    export PATH="/snap/bin:\$PATH"
  fi
fi
gem install bundler --no-document 2>/dev/null || true

# Clone or update
if [ -d "\$HOME/app/.git" ]; then
  cd "\$HOME/app" && git pull -q
else
  # Remove partial clone left by a previous failed deploy
  [ -d "\$HOME/repo" ] && ! [ -d "\$HOME/repo/.git" ] && rm -rf "\$HOME/repo"
  git clone -q --branch $branch $clone_url "\$HOME/repo" 2>/dev/null || \
    git clone -q $clone_url "\$HOME/repo"
  subdir="$subdir"
  if [ -n "\$subdir" ]; then
    ln -sfn "\$HOME/repo/\$subdir" "\$HOME/app"
  else
    ln -sfn "\$HOME/repo" "\$HOME/app"
  fi
fi

cd "\$HOME/app"
bundle config set --local path vendor/bundle
bundle install
# secret_key_base: master.key is gitignored, so generate a stable random key on first deploy
[ ! -f "\$HOME/.flowers_secret" ] && openssl rand -hex 64 > "\$HOME/.flowers_secret"
export SECRET_KEY_BASE=\$(cat "\$HOME/.flowers_secret")
RAILS_ENV=production bundle exec rails db:migrate 2>/dev/null || true
RAILS_ENV=production bundle exec rails db:seed 2>/dev/null || true
RAILS_ENV=production bundle exec rails assets:precompile 2>/dev/null || true

# Install systemd service (survives reboots and SSH session teardown)
BUNDLE_BIN="\$(which bundle)"
SVC_USER="\$(id -un)"
echo "SECRET_KEY_BASE=\$(cat \$HOME/.flowers_secret)" | sudo tee "\$HOME/.flowers_secret_env" > /dev/null
sudo chmod 600 "\$HOME/.flowers_secret_env"
sudo tee /etc/systemd/system/flowers.service > /dev/null << EOF
[Unit]
Description=Flowers Rails App
After=network.target

[Service]
Type=simple
User=\$SVC_USER
WorkingDirectory=\$HOME/app
Environment=RAILS_ENV=production
Environment=RAILS_SERVE_STATIC_FILES=true
Environment=PATH=\$(dirname \$BUNDLE_BIN):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EnvironmentFile=\$HOME/.flowers_secret_env
ExecStart=\$BUNDLE_BIN exec rails server -p $port -b 0.0.0.0 -e production
Restart=always
RestartSec=5
StandardOutput=append:\$HOME/app.log
StandardError=append:\$HOME/app.log

[Install]
WantedBy=multi-user.target
EOF
pkill -f "rails server" 2>/dev/null || true
sudo systemctl daemon-reload
sudo systemctl enable flowers
sudo systemctl restart flowers
echo "Flowers running on port $port"
SCRIPT
}

node_setup_script() {
    local clone_url="$1" branch="$2" subdir="$3" port="$4" public_ip="$5" host_override="${6:-$5}"
    cat <<SCRIPT
set -e
. /etc/os-release 2>/dev/null || true
case "\${ID:-}" in
  ol|rhel|centos|fedora|rocky|almalinux) IS_RPM=true ;;
  *) IS_RPM=false ;;
esac

if \$IS_RPM; then
  sudo dnf install -y git curl openssl
else
  sudo apt-get update -qq
  sudo apt-get install -y -qq git curl openssl
fi

# Node.js via nvm
if [ ! -d "\$HOME/.nvm" ]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
fi
export NVM_DIR="\$HOME/.nvm"
[ -s "\$NVM_DIR/nvm.sh" ] && . "\$NVM_DIR/nvm.sh"
nvm install --lts

# Clone or update
if [ -d "\$HOME/app/.git" ]; then
  cd "\$HOME/app" && git pull -q
else
  git clone -q --branch $branch $clone_url "\$HOME/app" 2>/dev/null || \
    git clone -q $clone_url "\$HOME/app"
fi

cd "\$HOME/app"
npm install --silent

# SSL certs (used internally; Caddy terminates TLS externally with a trusted cert)
if [ ! -f key.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
fi

# Restart
pkill -f "node index.js" 2>/dev/null || true; sleep 1

if [ -f run.sh ]; then
  # run.sh hardcodes APP_DIR to ~/Labyrinth — redirect it to our clone location
  sed -i "s|APP_DIR=.*|APP_DIR=\"\$HOME/app\"|" run.sh
  chmod +x run.sh
  # run.sh detects the raw public IP, writes config.json, patches main.js, and starts the app
  bash run.sh $port || true
  # run.sh sets: const host = '<raw-ip>'; — re-patch with our Caddy hostname
  sed -i "s/const host = '[^']*';/const host = '$host_override';/" public/main.js 2>/dev/null || true
  # When behind Caddy (sslip.io), clients must connect on 443 (Caddy's HTTPS port), not the internal app port
  [[ "$host_override" == *.sslip.io ]] && \
    sed -i "s/const port = [0-9]*;/const port = 443;/" public/main.js 2>/dev/null || true
else
  sed -i "s/34\\.57\\.176\\.17/$host_override/g" public/main.js 2>/dev/null || true
  nohup node index.js > "\$HOME/app.log" 2>&1 &
  echo \$! > "\$HOME/app.pid"
fi
echo "Labyrinth running on port $port"
SCRIPT
}

wasm_setup_script() {
    local clone_url="$1" branch="$2" subdir="$3" port="$4"
    cat <<SCRIPT
set -e
. /etc/os-release 2>/dev/null || true
case "\${ID:-}" in
  ol|rhel|centos|fedora|rocky|almalinux) IS_RPM=true ;;
  *) IS_RPM=false ;;
esac

if \$IS_RPM; then
  sudo dnf install -y git python3
else
  sudo apt-get update -qq
  sudo apt-get install -y -qq git python3
fi

# Clone or update
if [ -d "\$HOME/repo/.git" ]; then
  cd "\$HOME/repo" && git pull -q
else
  git clone -q --branch $branch $clone_url "\$HOME/repo" 2>/dev/null || \
    git clone -q $clone_url "\$HOME/repo"
fi

cd "\$HOME/repo/$subdir"

# Restart
pkill -f "python3 -m http.server" 2>/dev/null || true; sleep 1
nohup python3 -m http.server $port > "\$HOME/app.log" 2>&1 &
echo \$! > "\$HOME/app.pid"
echo "Fishing running on port $port"
SCRIPT
}

nextjs_setup_script() {
    local clone_url="$1" branch="$2" port="$3"
    cat <<SCRIPT
set -e
. /etc/os-release 2>/dev/null || true
case "\${ID:-}" in
  ol|rhel|centos|fedora|rocky|almalinux) IS_RPM=true ;;
  *) IS_RPM=false ;;
esac

if \$IS_RPM; then
  sudo dnf install -y git curl
else
  sudo apt-get update -qq
  sudo apt-get install -y -qq git curl
fi

# Node.js via nvm
if [ ! -d "\$HOME/.nvm" ]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
fi
export NVM_DIR="\$HOME/.nvm"
[ -s "\$NVM_DIR/nvm.sh" ] && . "\$NVM_DIR/nvm.sh"
nvm install --lts

# Clone or update
if [ -d "\$HOME/app/.git" ]; then
  cd "\$HOME/app" && git pull -q
else
  git clone -q --branch $branch $clone_url "\$HOME/app" 2>/dev/null || \
    git clone -q $clone_url "\$HOME/app"
fi

cd "\$HOME/app"

# Add swap to prevent OOM kill during build (idempotent; persisted via fstab)
if [ ! -f /swapfile ]; then
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
elif ! swapon --show | grep -q /swapfile; then
  sudo swapon /swapfile
fi

npm install --silent
# Build happens locally then gets rsynced — avoids OOM on small VMs.

# Install systemd service for reliable restarts across reboots and SSH sessions
NODE_BIN="\$(readlink -f "\$(which node)")"
NPM_BIN="\$(readlink -f "\$(which npm)")"
NODE_DIR="\$(dirname "\$NODE_BIN")"
SVC_USER="\$(id -un)"
sudo tee /etc/systemd/system/portfolio.service > /dev/null << EOF
[Unit]
Description=Portfolio Next.js
After=network.target

[Service]
Type=simple
User=\$SVC_USER
WorkingDirectory=\$HOME/app
Environment=PATH=\$NODE_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=\$NPM_BIN start
Restart=always
RestartSec=5
StandardOutput=append:\$HOME/app/logs/portfolio.log
StandardError=append:\$HOME/app/logs/portfolio.log

[Install]
WantedBy=multi-user.target
EOF
mkdir -p "\$HOME/app/logs"
sudo systemctl daemon-reload
sudo systemctl enable portfolio
# Service is started after the local build is rsynced (see sync_nextjs_build_to_vm)
echo "Portfolio node_modules ready on port $port"
SCRIPT
}

caddy_setup_script() {
    local fqdn="$1" internal_port="$2" backend_scheme="${3:-http}"
    # Pre-compute the Caddyfile content (variables expanded here in calling shell)
    local caddyfile_cmd
    # The global block sets email off so Caddy registers with Let's Encrypt using no
    # contact address — the literal "default" string it falls back to is not a valid
    # email and causes HTTP 400 invalidContact from the production ACME server.
    # email is required to be RFC-5321 valid; Let's Encrypt checks format only, never
    # verifies the mailbox. Using a valid placeholder avoids the "mailto:default" /
    # "mailto:off" rejections that occur when Caddy falls back to its built-in defaults.
    local acme_email="noreply@sslip.io"
    if [ "$backend_scheme" = "https" ]; then
        caddyfile_cmd="printf '{\n    email ${acme_email}\n}\n${fqdn} {\n    reverse_proxy https://localhost:${internal_port} {\n        transport http {\n            tls_insecure_skip_verify\n        }\n    }\n}\n'"
    else
        caddyfile_cmd="printf '{\n    email ${acme_email}\n}\n${fqdn} {\n    reverse_proxy localhost:${internal_port}\n}\n'"
    fi
    cat <<SCRIPT
set -e
. /etc/os-release 2>/dev/null || true
case "\${ID:-}" in
  ol|rhel|centos|fedora|rocky|almalinux) IS_RPM=true ;;
  *) IS_RPM=false ;;
esac

if \$IS_RPM; then
  # Oracle Linux / RHEL: install Caddy via COPR
  sudo dnf install -y 'dnf-command(copr)' 2>/dev/null || sudo dnf install -y dnf-plugins-core
  sudo dnf copr enable -y @caddy/caddy
  sudo dnf install -y caddy
  # Open ports 80/443 in firewalld (Oracle Linux 9 has firewalld active by default)
  sudo firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
  sudo firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || true
  sudo firewall-cmd --reload 2>/dev/null || true
else
  # Ubuntu / Debian: install Caddy via Cloudsmith apt repo
  sudo apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg
  curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' -o /tmp/caddy.gpg
  sudo rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  sudo gpg --batch --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg /tmp/caddy.gpg
  rm -f /tmp/caddy.gpg
  curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
      sudo tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
  sudo apt-get update -qq
  sudo apt-get install -y -qq caddy
fi
$caddyfile_cmd | sudo tee /etc/caddy/Caddyfile > /dev/null
# Clear any cached staging/failed certs so Caddy requests a fresh production cert
sudo systemctl stop caddy 2>/dev/null || true
sudo rm -rf /var/lib/caddy/.local/share/caddy/acme/
sudo systemctl enable caddy
sudo systemctl start caddy
echo "Caddy configured: ${fqdn} -> ${backend_scheme}://localhost:${internal_port}"
SCRIPT
}

# ----------------------------------------------------------
# Build the portfolio locally and push the .next output to the VM.
# Called after nextjs_setup_script/app_refresh_script so node_modules
# are already in place; the VM never runs the build itself (OOM risk).
# ----------------------------------------------------------
sync_nextjs_build_to_vm() {
    local ip="$1"
    log "Building portfolio locally..."
    (cd "$SCRIPT_DIR" && npm run build) \
        || err "Local Next.js build failed"
    log "Uploading .next build to $ip..."
    rsync -az --delete \
        -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR" \
        "$SCRIPT_DIR/.next/" \
        "${SSH_REMOTE_USER}@${ip}:~/app/.next/"
    ssh_to "$ip" "sudo systemctl restart portfolio"
    log "Portfolio started with fresh build."
}

# ----------------------------------------------------------
# Cloud providers — each returns the VM's public IP via stdout
# ----------------------------------------------------------

provision_aws() {
    local id="$1" region="$2" auth_key="$3" port="$4"
    local vm_name="portfolio-$id"

    # Parse JSON credentials file — supports both flat and nested (create-access-key) formats:
    #   { "aws_access_key_id": "...", "aws_secret_access_key": "..." }
    #   { "AccessKey": { "AccessKeyId": "...", "SecretAccessKey": "..." } }
    local key_id secret_key
    key_id=$(python3 -c "
import json; d=json.load(open('$auth_key', encoding='utf-8-sig'))
ak=d.get('AccessKey',d)
print(ak.get('AccessKeyId') or ak.get('aws_access_key_id',''))")
    secret_key=$(python3 -c "
import json; d=json.load(open('$auth_key', encoding='utf-8-sig'))
ak=d.get('AccessKey',d)
print(ak.get('SecretAccessKey') or ak.get('aws_secret_access_key',''))")
    export AWS_ACCESS_KEY_ID="$key_id"
    export AWS_SECRET_ACCESS_KEY="$secret_key"
    unset AWS_SHARED_CREDENTIALS_FILE
    local sg_name="portfolio-${id}-sg"

    ensure_ssh_key

    # Import SSH key pair if not present
    aws ec2 describe-key-pairs --key-names "portfolio-deploy" --region "$region" &>/dev/null || \
        aws ec2 import-key-pair \
            --key-name "portfolio-deploy" \
            --public-key-material "fileb://${SSH_KEY}.pub" \
            --region "$region" --output text > /dev/null

    # Security group
    local sg_id
    sg_id=$(aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=$sg_name" \
        --query "SecurityGroups[0].GroupId" --output text --region "$region" 2>/dev/null || echo "None")
    if [ "$sg_id" = "None" ] || [ -z "$sg_id" ]; then
        sg_id=$(aws ec2 create-security-group \
            --group-name "$sg_name" \
            --description "Portfolio $id" \
            --region "$region" --output text --query GroupId)
    fi
    # Ensure required ports are open — idempotent, ignores InvalidPermission.Duplicate
    aws ec2 authorize-security-group-ingress --group-id "$sg_id" --protocol tcp --port 22  --cidr 0.0.0.0/0 --region "$region" --output text > /dev/null 2>&1 || true
    aws ec2 authorize-security-group-ingress --group-id "$sg_id" --protocol tcp --port 80  --cidr 0.0.0.0/0 --region "$region" --output text > /dev/null 2>&1 || true
    aws ec2 authorize-security-group-ingress --group-id "$sg_id" --protocol tcp --port 443 --cidr 0.0.0.0/0 --region "$region" --output text > /dev/null 2>&1 || true

    # Find existing instance in any reusable state; create only if none exists
    local instance_id
    instance_id=$(aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=$vm_name" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query "Reservations[].Instances[] | sort_by(@,&LaunchTime)[-1].InstanceId" \
        --output text --region "$region" 2>/dev/null || echo "")
    if [ "$instance_id" = "None" ] || [ -z "$instance_id" ]; then
        local ami
        ami=$(aws ec2 describe-images \
            --owners 099720109477 \
            --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
                      "Name=state,Values=available" \
            --query "sort_by(Images,&CreationDate)[-1].ImageId" \
            --output text --region "$region") || err "Failed to find Ubuntu AMI in $region"
        [ -z "$ami" ] || [ "$ami" = "None" ] && err "No Ubuntu 22.04 AMI found in $region"
        log "Launching EC2 instance ($ami, t2.micro) in $region..."
        instance_id=$(aws ec2 run-instances \
            --image-id "$ami" --instance-type t2.micro \
            --key-name "portfolio-deploy" \
            --security-group-ids "$sg_id" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$vm_name}]" \
            --query "Instances[0].InstanceId" --output text --region "$region") \
            || err "aws ec2 run-instances failed — check IAM permissions (ec2:RunInstances)"
        [ -z "$instance_id" ] || [ "$instance_id" = "None" ] && err "run-instances returned no instance ID"
        log "Waiting for EC2 instance $instance_id to start..."
        aws ec2 wait instance-running --instance-ids "$instance_id" --region "$region"
    else
        local state
        state=$(aws ec2 describe-instances \
            --instance-ids "$instance_id" \
            --query "Reservations[0].Instances[0].State.Name" \
            --output text --region "$region")
        case "$state" in
            running) ;;
            pending)
                log "Waiting for EC2 instance $instance_id to become running..."
                aws ec2 wait instance-running --instance-ids "$instance_id" --region "$region"
                ;;
            stopped)
                log "Starting stopped EC2 instance $instance_id..."
                aws ec2 start-instances --instance-ids "$instance_id" --region "$region" --output text > /dev/null
                aws ec2 wait instance-running --instance-ids "$instance_id" --region "$region"
                ;;
            stopping)
                log "Waiting for EC2 instance $instance_id to stop before restart..."
                aws ec2 wait instance-stopped --instance-ids "$instance_id" --region "$region"
                aws ec2 start-instances --instance-ids "$instance_id" --region "$region" --output text > /dev/null
                aws ec2 wait instance-running --instance-ids "$instance_id" --region "$region"
                ;;
            *)
                warn "Unexpected AWS instance state '$state' for $instance_id; continuing"
                ;;
        esac
    fi

    local public_ip=""
    for _ in {1..24}; do
        public_ip=$(aws ec2 describe-instances \
            --instance-ids "$instance_id" \
            --query "Reservations[0].Instances[0].PublicIpAddress" \
            --output text --region "$region")
        if [ -n "$public_ip" ] && [ "$public_ip" != "None" ]; then
            break
        fi
        sleep 5
    done
    [ -z "$public_ip" ] || [ "$public_ip" = "None" ] && \
        err "Could not determine public IP for EC2 instance $instance_id in $region"
    echo "$public_ip"
}

provision_azure() {
    local id="$1" region="$2" auth_key="$3" port="$4" dns_label="${5:-}"
    local rg="portfolio-rg"
    local vm_name="portfolio-$id"

    ensure_ssh_key

    # Parse service principal JSON — handles both az ad sp create-for-rbac formats:
    #   --sdk-auth format:  clientId / clientSecret / tenantId / subscriptionId
    #   standard SP format: appId   / password     / tenant   (no subscriptionId)
    local client_id client_secret tenant_id subscription_id
    client_id=$(python3 -c "
import json; d=json.load(open('$auth_key', encoding='utf-8-sig'))
print(d.get('clientId') or d.get('appId',''))")
    client_secret=$(python3 -c "
import json; d=json.load(open('$auth_key', encoding='utf-8-sig'))
print(d.get('clientSecret') or d.get('password',''))")
    tenant_id=$(python3 -c "
import json; d=json.load(open('$auth_key', encoding='utf-8-sig'))
print(d.get('tenantId') or d.get('tenant',''))")
    subscription_id=$(python3 -c "
import json; d=json.load(open('$auth_key', encoding='utf-8-sig'))
print(d.get('subscriptionId',''))")

    az login --service-principal \
        --username "$client_id" \
        --password "$client_secret" \
        --tenant "$tenant_id" \
        --output none

    if [ -n "$subscription_id" ]; then
        az account set --subscription "$subscription_id" --output none
    else
        subscription_id=$(az account list --query "[0].id" -o tsv 2>/dev/null || echo "")
        [ -n "$subscription_id" ] \
            && az account set --subscription "$subscription_id" --output none \
            || err "No Azure subscriptions found for this service principal. Ensure it has a role assignment (e.g. Contributor) on a subscription."
    fi

    az group create --name "$rg" --location "$region" --output none 2>/dev/null || true

    local state
    state=$(az vm show --name "$vm_name" --resource-group "$rg" \
        --query "provisioningState" -o tsv 2>/dev/null || echo "")
    if [ -z "$state" ]; then
        local vm_size
        vm_size=$(cloud_get "$id" vmSize)
        vm_size="${vm_size:-Standard_DS1_v2}"
        log "Using VM size: $vm_size"
        local create_args=(
            --name "$vm_name" --resource-group "$rg"
            --image Ubuntu2204 --size "$vm_size"
            --admin-username ubuntu
            --ssh-key-values "${SSH_KEY}.pub"
            --output none
        )
        [ -n "$dns_label" ] && create_args+=(--public-ip-address-dns-name "$dns_label")
        az vm create "${create_args[@]}"
        if [ -n "$dns_label" ]; then
            az vm open-port --name "$vm_name" --resource-group "$rg" --port 80  --priority 900 --output none
            az vm open-port --name "$vm_name" --resource-group "$rg" --port 443 --priority 901 --output none
        else
            az vm open-port --name "$vm_name" --resource-group "$rg" --port "$port" --priority 900 --output none
        fi
    else
        local power_state
        power_state=$(az vm get-instance-view --name "$vm_name" --resource-group "$rg" \
            --query "instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus | [0]" -o tsv 2>/dev/null || echo "")
        if [ "$power_state" != "VM running" ]; then
            log "Starting existing Azure VM $vm_name (state: ${power_state:-unknown})..."
            az vm start --name "$vm_name" --resource-group "$rg" --output none
        fi
    fi

    if [ -n "$dns_label" ]; then
        echo "${dns_label}.${region}.cloudapp.azure.com"
    else
        az vm show --name "$vm_name" --resource-group "$rg" \
            --show-details --query "publicIps" -o tsv
    fi
}

provision_gcp() {
    local id="$1" region="$2" auth_key="$3" port="$4"
    local zone="${region}-a"
    local vm_name="portfolio-$id"
    local gcp_project
    gcp_project=$(python3 -c "import json; print(json.load(open('$auth_key', encoding='utf-8-sig'))['project_id'])")

    ensure_ssh_key
    gcloud auth activate-service-account --key-file="$auth_key" --quiet
    gcloud config set project "$gcp_project" --quiet

    # Firewall rules — app port for direct access + 80/443 for Caddy/sslip.io
    gcloud compute firewall-rules describe "portfolio-app" --quiet &>/dev/null || \
        gcloud compute firewall-rules create "portfolio-app" \
            --allow "tcp:$port" --target-tags portfolio-server --quiet 2>/dev/null || true
    gcloud compute firewall-rules describe "portfolio-caddy" --quiet &>/dev/null || \
        gcloud compute firewall-rules create "portfolio-caddy" \
            --allow "tcp:80,tcp:443" --target-tags portfolio-server --quiet 2>/dev/null || true

    # Instance
    local existing
    existing=$(gcloud compute instances describe "$vm_name" \
        --zone="$zone" --format="value(status)" 2>/dev/null || echo "")
    if [ -z "$existing" ]; then
        local pub_key="ubuntu:$(cat "${SSH_KEY}.pub")"
        # This workload does not call GCP APIs from inside the VM, so avoid
        # relying on the default Compute Engine service account existing.
        gcloud compute instances create "$vm_name" \
            --zone="$zone" --machine-type=e2-micro \
            --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
            --tags=portfolio-server \
            --no-service-account --no-scopes \
            --metadata="ssh-keys=$pub_key" \
            --quiet
    elif [ "$existing" = "TERMINATED" ]; then
        log "Starting stopped GCP instance $vm_name..."
        gcloud compute instances start "$vm_name" --zone="$zone" --quiet
    elif [ "$existing" = "SUSPENDED" ]; then
        log "Resuming suspended GCP instance $vm_name..."
        gcloud compute instances resume "$vm_name" --zone="$zone" --quiet
    fi

    local status waited
    waited=0
    while true; do
        status=$(gcloud compute instances describe "$vm_name" \
            --zone="$zone" --format="value(status)" 2>/dev/null || echo "")
        [ "$status" = "RUNNING" ] && break
        waited=$((waited + 5))
        [ "$waited" -ge 180 ] && err "Timed out waiting for GCP instance $vm_name to be RUNNING (last state: ${status:-unknown})"
        sleep 5
    done

    gcloud compute instances describe "$vm_name" --zone="$zone" \
        --format="value(networkInterfaces[0].accessConfigs[0].natIP)"
}

provision_oci() {
    local id="$1" region="$2" auth_key="$3" port="$4"
    local vm_name="portfolio-$id"

    # auth_key is a JSON file containing OCI-specific fields alongside the config path.
    # OCI CLI cannot derive compartment/subnet from the config file alone.
    local config_file profile compartment_id subnet_id tenancy_id
    config_file=$(python3  -c "import json; d=json.load(open('$auth_key', encoding='utf-8-sig')); print(d.get('configFile', '$HOME/.oci/config'))")
    profile=$(python3      -c "import json; d=json.load(open('$auth_key', encoding='utf-8-sig')); print(d.get('profile', 'DEFAULT'))")
    compartment_id=$(python3 -c "import json; print(json.load(open('$auth_key', encoding='utf-8-sig'))['compartmentId'])")
    subnet_id=$(python3      -c "import json; print(json.load(open('$auth_key', encoding='utf-8-sig'))['subnetId'])")
    config_file="${config_file/#\~/$HOME}"
    [ -f "$config_file" ] || err "OCI config file not found: $config_file"
    if [[ "$compartment_id" == ocid1.tenancy* ]]; then
        warn "compartmentId is a tenancy OCID (root compartment). Launching in root often fails without tenancy-wide policies."
        warn "If this fails, use a dedicated compartment OCID and a subnet in that same compartment."
    fi
    tenancy_id=$(python3 -c "
import configparser
cfg = configparser.ConfigParser()
cfg.read('$config_file')
print(cfg.get('$profile', 'tenancy', fallback=''))
" 2>/dev/null || echo "")

    export OCI_CLI_CONFIG_FILE="$config_file"
    local -a oci_flags=(--profile "$profile" --region "$region")

    ensure_ssh_key

    # Preflight network checks to surface common OCI misconfigurations early.
    # OCI routing + firewall are separate concerns; both must allow traffic.
    local subnet_public subnet_compartment_id route_table_id igw_target igw_enabled
    subnet_public=$(oci network subnet get "${oci_flags[@]}" \
        --subnet-id "$subnet_id" \
        --query 'data."prohibit-public-ip-on-vnic"' --raw-output 2>/dev/null || echo "")
    if [ "$subnet_public" = "true" ]; then
        err "OCI subnet $subnet_id is private (prohibit-public-ip-on-vnic=true). Use a public subnet for direct SSH/HTTPS deploys."
    fi
    subnet_compartment_id=$(oci network subnet get "${oci_flags[@]}" \
        --subnet-id "$subnet_id" \
        --query 'data."compartment-id"' --raw-output 2>/dev/null || echo "")

    local compute_compartment_id="$compartment_id"
    if [ -n "$subnet_compartment_id" ] && [ "$subnet_compartment_id" != "null" ] && [ "$subnet_compartment_id" != "$compartment_id" ]; then
        warn "OCI authKey compartmentId differs from subnet compartment."
        warn "Using subnet compartment for compute operations: $subnet_compartment_id"
        warn "Update oci authKey compartmentId to match subnet compartment to avoid permission errors."
        compute_compartment_id="$subnet_compartment_id"
    fi

    route_table_id=$(oci network subnet get "${oci_flags[@]}" \
        --subnet-id "$subnet_id" \
        --query 'data."route-table-id"' --raw-output 2>/dev/null || echo "")
    if [ -z "$route_table_id" ] || [ "$route_table_id" = "null" ]; then
        warn "Could not determine route table for subnet $subnet_id. Ensure it has 0.0.0.0/0 -> Internet Gateway."
    else
        igw_target=$(oci network route-table get "${oci_flags[@]}" \
            --rt-id "$route_table_id" \
            --query 'data."route-rules"[?destination==`0.0.0.0/0`]."network-entity-id" | [0]' \
            --raw-output 2>/dev/null || echo "")
        if [ -z "$igw_target" ] || [ "$igw_target" = "null" ]; then
            warn "Route table $route_table_id has no default route (0.0.0.0/0). Add a route to an Internet Gateway."
        elif [[ "$igw_target" != ocid1.internetgateway* ]]; then
            warn "Route table $route_table_id default route target is not an Internet Gateway ($igw_target). Public inbound traffic may fail."
        else
            igw_enabled=$(oci network internet-gateway get "${oci_flags[@]}" \
                --ig-id "$igw_target" \
                --query 'data."is-enabled"' --raw-output 2>/dev/null || echo "")
            [ "$igw_enabled" = "false" ] && warn "Internet Gateway $igw_target is disabled."
        fi
    fi

    # Security-list sanity check: verify common inbound TCP ports from 0.0.0.0/0.
    # If you use NSGs instead, these warnings can be ignored.
    local -a security_list_ids missing_ports
    local check_port allowed sl_id rules_json
    mapfile -t security_list_ids < <(
        oci network subnet get "${oci_flags[@]}" \
            --subnet-id "$subnet_id" \
            --query 'data."security-list-ids"[]' --raw-output 2>/dev/null || true
    )
    for check_port in 22 80 443 "$port"; do
        allowed="no"
        for sl_id in "${security_list_ids[@]}"; do
            rules_json=$(oci network security-list get "${oci_flags[@]}" \
                --security-list-id "$sl_id" \
                --query 'data."ingress-security-rules"' 2>/dev/null || echo "[]")
            if python3 -c '
import json, sys
port = int(sys.argv[1])
try:
    rules = json.loads(sys.argv[2])
except Exception:
    sys.exit(1)

def allows(rule):
    src = rule.get("source")
    if src != "0.0.0.0/0":
        return False
    proto = str(rule.get("protocol", "")).lower()
    if proto == "all":
        return True
    if proto not in ("6", "tcp"):
        return False
    tcp = rule.get("tcp-options") or {}
    dst = tcp.get("destination-port-range")
    if not dst:
        return True
    lo = int(dst.get("min", 1))
    hi = int(dst.get("max", 65535))
    return lo <= port <= hi

sys.exit(0 if any(allows(rule) for rule in rules) else 1)
' "$check_port" "$rules_json" >/dev/null 2>&1
            then
                allowed="yes"
                break
            fi
        done
        [ "$allowed" = "yes" ] || missing_ports+=("$check_port")
    done
    if [ ${#missing_ports[@]} -gt 0 ]; then
        warn "Subnet security lists may block required inbound ports: ${missing_ports[*]} (from 0.0.0.0/0)."
        warn "If you rely on NSGs instead of security lists, ensure those NSG rules allow the same ports."
    fi

    # Find existing instance in any reusable state; create only if none exists
    local instance_id
    instance_id=$(oci compute instance list "${oci_flags[@]}" \
        --compartment-id "$compute_compartment_id" \
        --display-name "$vm_name" \
        --all \
        --query 'data[?"lifecycle-state"!=`TERMINATED`] | sort_by(@,&"time-created")[-1].id' --raw-output 2>/dev/null || echo "")

    if [ -z "$instance_id" ] || [ "$instance_id" = "null" ]; then
        # Resolve latest Oracle Linux 9 image for ARM64 (VM.Standard.A1.Flex — Always Free eligible)
        local image_id
        image_id=$(oci compute image list "${oci_flags[@]}" \
            --compartment-id "$compute_compartment_id" \
            --operating-system "Oracle Linux" \
            --operating-system-version "9" \
            --shape "VM.Standard.A1.Flex" \
            --sort-by TIMECREATED --sort-order DESC \
            --all \
            --query 'data[0].id' --raw-output)
        [ -z "$image_id" ] || [ "$image_id" = "null" ] && \
            err "No Oracle Linux 9 image found compatible with VM.Standard.A1.Flex in compartment $compartment_id"

        # Use first availability domain in the region
        local ad
        ad=$(oci iam availability-domain list "${oci_flags[@]}" \
            --compartment-id "${tenancy_id:-$compartment_id}" \
            --query 'data[0].name' --raw-output)
        [ -z "$ad" ] || [ "$ad" = "null" ] && err "Could not resolve an OCI availability domain in region $region"

        log "Launching OCI instance $vm_name in $ad..."
        local launch_out launch_rc
        set +e
        launch_out=$(oci compute instance launch "${oci_flags[@]}" \
            --compartment-id "$compute_compartment_id" \
            --display-name "$vm_name" \
            --availability-domain "$ad" \
            --shape "VM.Standard.A1.Flex" \
            --shape-config '{"ocpus":1,"memoryInGBs":6}' \
            --image-id "$image_id" \
            --subnet-id "$subnet_id" \
            --assign-public-ip true \
            --ssh-authorized-keys-file "${SSH_KEY}.pub" \
            --wait-for-state RUNNING \
            --query 'data.id' --raw-output 2>&1)
        launch_rc=$?
        set -e
        if [ $launch_rc -ne 0 ]; then
            if echo "$launch_out" | grep -q "NotAuthorizedOrNotFound"; then
                err "OCI launch_instance was rejected (NotAuthorizedOrNotFound). Check: 1) compartmentId in oci authKey, 2) subnetId exists in $region, 3) IAM policy allows instance/network in compartment $compute_compartment_id, 4) if compartmentId is ocid1.tenancy..., you likely need tenancy-wide rights or a non-root compartment. Raw error: $launch_out"
            fi
            err "OCI launch_instance failed: $launch_out"
        fi
        instance_id="$(echo "$launch_out" | tr -d '\r' | tail -n 1 | tr -d '[:space:]')"
        [ -z "$instance_id" ] || [ "$instance_id" = "null" ] && err "OCI launch returned no instance OCID."
        sleep 20  # allow SSH daemon to start
    else
        local state
        state=$(oci compute instance get "${oci_flags[@]}" \
            --instance-id "$instance_id" \
            --query 'data."lifecycle-state"' --raw-output 2>/dev/null || echo "")
        case "$state" in
            RUNNING) ;;
            STOPPED)
                log "Starting stopped OCI instance $vm_name..."
                oci compute instance action "${oci_flags[@]}" \
                    --instance-id "$instance_id" \
                    --action START \
                    --wait-for-state RUNNING > /dev/null
                sleep 20
                ;;
            STOPPING)
                log "Waiting for OCI instance $vm_name to stop before restart..."
                oci compute instance get "${oci_flags[@]}" \
                    --instance-id "$instance_id" \
                    --wait-for-state STOPPED \
                    --max-wait-seconds 600 > /dev/null
                oci compute instance action "${oci_flags[@]}" \
                    --instance-id "$instance_id" \
                    --action START \
                    --wait-for-state RUNNING > /dev/null
                sleep 20
                ;;
            PROVISIONING|STARTING)
                log "Waiting for OCI instance $vm_name to become RUNNING..."
                oci compute instance get "${oci_flags[@]}" \
                    --instance-id "$instance_id" \
                    --wait-for-state RUNNING \
                    --max-wait-seconds 600 > /dev/null
                sleep 20
                ;;
            *)
                warn "Unexpected OCI instance state '$state' for $vm_name; continuing"
                ;;
        esac
    fi

    local public_ip=""
    for _ in {1..24}; do
        public_ip=$(oci compute instance list-vnics "${oci_flags[@]}" \
            --instance-id "$instance_id" \
            --query 'data[0]."public-ip"' --raw-output 2>/dev/null || echo "")
        if [ -n "$public_ip" ] && [ "$public_ip" != "null" ]; then
            break
        fi
        sleep 5
    done
    [ -z "$public_ip" ] || [ "$public_ip" = "null" ] && \
        err "OCI instance $vm_name has no public IP. Check subnet public-IP setting and network route/security configuration."
    echo "$public_ip"
}

# ----------------------------------------------------------
# Object storage upload functions for wasm projects.
# Each function uploads every file in local_dir to the bucket,
# sets the correct Content-Type (critical for .wasm files), and
# prints the public index.html URL to stdout.
# ----------------------------------------------------------

upload_wasm_oci() {
    local local_dir="$1" bucket="$2" auth_key="$3" region="$4"

    local config_file profile compartment_id
    config_file=$(python3 -c "
import json,os,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
print(os.path.expanduser(d.get('configFile','~/.oci/config')))
" "$auth_key")
    profile=$(python3 -c "
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8-sig')).get('profile','DEFAULT'))
" "$auth_key")
    compartment_id=$(python3 -c "
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8-sig')).get('compartmentId',''))
" "$auth_key")

    local oci_flags=(--config-file "$config_file" --profile "$profile")
    local namespace
    namespace=$(oci os ns get "${oci_flags[@]}" --query 'data' --raw-output)

    # Create bucket if it doesn't exist
    oci os bucket create "${oci_flags[@]}" \
        --compartment-id "$compartment_id" \
        --name "$bucket" \
        --namespace "$namespace" \
        --public-access-type ObjectReadWithoutList 2>/dev/null || true

    # Upload every file, preserving relative paths, with correct Content-Type
    while IFS= read -r -d '' file; do
        local name="${file#"$local_dir"/}"
        local mime
        mime=$(get_mime_type "$file")
        oci os object put "${oci_flags[@]}" \
            --bucket-name "$bucket" \
            --namespace "$namespace" \
            --file "$file" \
            --name "$name" \
            --content-type "$mime" \
            --force > /dev/null
    done < <(find "$local_dir" -type f -print0)

    echo "https://objectstorage.${region}.oraclecloud.com/n/${namespace}/b/${bucket}/o/index.html"
}

upload_wasm_aws() {
    local local_dir="$1" bucket="$2" auth_key="$3" region="$4"

    local key_id secret_key
    key_id=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
ak=d.get('AccessKey',d)
print(ak.get('AccessKeyId') or ak.get('aws_access_key_id',''))
" "$auth_key")
    secret_key=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
ak=d.get('AccessKey',d)
print(ak.get('SecretAccessKey') or ak.get('aws_secret_access_key',''))
" "$auth_key")
    export AWS_ACCESS_KEY_ID="$key_id"
    export AWS_SECRET_ACCESS_KEY="$secret_key"
    unset AWS_SHARED_CREDENTIALS_FILE

    # Create bucket (us-east-1 has no LocationConstraint; all other regions do)
    if [ "$region" = "us-east-1" ]; then
        aws s3api create-bucket --bucket "$bucket" --region "$region" 2>/dev/null || true
    else
        aws s3api create-bucket --bucket "$bucket" --region "$region" \
            --create-bucket-configuration LocationConstraint="$region" 2>/dev/null || true
    fi

    # Allow public access (S3 defaults block it)
    aws s3api put-public-access-block --bucket "$bucket" \
        --public-access-block-configuration \
        "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

    # Public read bucket policy
    aws s3api put-bucket-policy --bucket "$bucket" --policy "{
        \"Version\":\"2012-10-17\",
        \"Statement\":[{
            \"Effect\":\"Allow\",
            \"Principal\":\"*\",
            \"Action\":\"s3:GetObject\",
            \"Resource\":\"arn:aws:s3:::${bucket}/*\"
        }]
    }"

    # Sync files; set Content-Type per file
    while IFS= read -r -d '' file; do
        local name="${file#"$local_dir"/}"
        local mime
        mime=$(get_mime_type "$file")
        aws s3 cp "$file" "s3://${bucket}/${name}" \
            --region "$region" \
            --content-type "$mime" > /dev/null
    done < <(find "$local_dir" -type f -print0)

    echo "https://${bucket}.s3.${region}.amazonaws.com/index.html"
}

upload_wasm_gcp() {
    local local_dir="$1" bucket="$2" auth_key="$3" region="$4"

    local gcp_project
    gcp_project=$(python3 -c "
import json,sys
print(json.load(open(sys.argv[1],encoding='utf-8-sig'))['project_id'])
" "$auth_key")
    gcloud auth activate-service-account --key-file="$auth_key" --quiet
    gcloud config set project "$gcp_project" --quiet

    # Create bucket if needed
    gsutil mb -l "$region" "gs://$bucket" 2>/dev/null || true

    # Grant public read
    gsutil iam ch allUsers:objectViewer "gs://$bucket"

    # Upload each file with correct Content-Type
    while IFS= read -r -d '' file; do
        local name="${file#"$local_dir"/}"
        local mime
        mime=$(get_mime_type "$file")
        gsutil -h "Content-Type:${mime}" cp "$file" "gs://${bucket}/${name}" > /dev/null
    done < <(find "$local_dir" -type f -print0)

    echo "https://storage.googleapis.com/${bucket}/index.html"
}

upload_wasm_azure() {
    local local_dir="$1" bucket="$2" storage_account="$3" auth_key="$4" region="$5"

    local client_id client_secret tenant_id subscription_id
    client_id=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
print(d.get('clientId') or d.get('appId',''))
" "$auth_key")
    client_secret=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
print(d.get('clientSecret') or d.get('password',''))
" "$auth_key")
    tenant_id=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
print(d.get('tenantId') or d.get('tenant',''))
" "$auth_key")
    subscription_id=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
print(d.get('subscriptionId',''))
" "$auth_key")
    az login --service-principal \
        --username "$client_id" --password "$client_secret" \
        --tenant "$tenant_id" --output none
    [ -n "$subscription_id" ] && az account set --subscription "$subscription_id"

    local rg="portfolio-rg"
    az group create --name "$rg" --location "$region" --output none 2>/dev/null || true

    # Create storage account (name must be globally unique, lowercase, ≤24 chars)
    az storage account create \
        --name "$storage_account" \
        --resource-group "$rg" \
        --location "$region" \
        --sku Standard_LRS \
        --kind StorageV2 \
        --allow-blob-public-access true \
        --output none 2>/dev/null || true

    # Create container with public blob access
    az storage container create \
        --name "$bucket" \
        --account-name "$storage_account" \
        --public-access blob \
        --auth-mode login \
        --output none 2>/dev/null || true

    # Upload each file with correct Content-Type
    while IFS= read -r -d '' file; do
        local name="${file#"$local_dir"/}"
        local mime
        mime=$(get_mime_type "$file")
        az storage blob upload \
            --account-name "$storage_account" \
            --container-name "$bucket" \
            --name "$name" \
            --file "$file" \
            --content-type "$mime" \
            --auth-mode login \
            --overwrite \
            --output none
    done < <(find "$local_dir" -type f -print0)

    echo "https://${storage_account}.blob.core.windows.net/${bucket}/index.html"
}

# ----------------------------------------------------------
# Clone (or pull) a wasm project locally, then upload to
# the configured object storage bucket.
# Sets USE_VM=false path for type=wasm projects with a bucket.
# ----------------------------------------------------------
deploy_wasm_to_storage() {
    local id="$1"
    local provider repo_url auth_key region bucket storage_account
    provider=$(cloud_get "$id" provider)
    repo_url=$(cloud_get "$id" repoUrl)
    auth_key="$(resolve_cloud_path "$(cloud_get "$id" authKey)")"
    region=$(cloud_get "$id" region)
    bucket=$(cloud_get "$id" bucket)
    storage_account=$(cloud_get "$id" storageAccount)

    read -r clone_url branch subdir <<< "$(parse_repo_url "$repo_url")"

    # Keep a local clone of the repo for uploads (avoids needing a VM)
    local build_dir="$SCRIPT_DIR/.wasm_builds/$id"
    mkdir -p "$build_dir"
    if [ -d "$build_dir/.git" ]; then
        log "$id: pulling latest wasm sources..."
        git -C "$build_dir" pull -q
    else
        log "$id: cloning wasm sources..."
        git clone -q --branch "$branch" "$clone_url" "$build_dir" 2>/dev/null || \
            git clone -q "$clone_url" "$build_dir"
    fi

    local local_dir="$build_dir"
    [ -n "$subdir" ] && local_dir="$build_dir/$subdir"
    [ -d "$local_dir" ] || err "$id: subdir '$subdir' not found in cloned repo"

    log "$id: uploading to $provider object storage (bucket=$bucket)..."
    local url
    case "$provider" in
        oci)   url=$(upload_wasm_oci   "$local_dir" "$bucket" "$auth_key" "$region") ;;
        aws)   url=$(upload_wasm_aws   "$local_dir" "$bucket" "$auth_key" "$region") ;;
        gcp)   url=$(upload_wasm_gcp   "$local_dir" "$bucket" "$auth_key" "$region") ;;
        azure) url=$(upload_wasm_azure "$local_dir" "$bucket" "$storage_account" "$auth_key" "$region") ;;
        *)     err "Unknown provider for wasm storage: $provider" ;;
    esac

    save_host "$url" "$id"
    write_env_url "$id" "$url"
    log "$id → $url (written to .env.local)"
}

# ----------------------------------------------------------
# Deploy a project to a provisioned VM
# ----------------------------------------------------------
deploy_to_vm() {
    local id="$1" type="$2" port="$3" repo_url="$4" ip="$5" fqdn="${6:-}"
    read -r clone_url branch subdir <<< "$(parse_repo_url "$repo_url")"

    wait_for_ssh "$ip"
    log "Deploying $id to $ip (type=$type, port=$port)..."
    case "$type" in
        rails)  rails_setup_script  "$clone_url" "$branch" "$subdir" "$port" ;;
        node)   node_setup_script   "$clone_url" "$branch" "$subdir" "$port" "$ip" "${fqdn:-$ip}" ;;
        wasm)   wasm_setup_script   "$clone_url" "$branch" "$subdir" "$port" ;;
        nextjs) nextjs_setup_script "$clone_url" "$branch" "$port" ;;
        *)      err "Unknown project type: $type" ;;
    esac | ssh_to "$ip" bash

    if [ -n "$fqdn" ]; then
        log "Configuring Caddy on $ip for https://$fqdn -> http://localhost:$port..."
        caddy_setup_script "$fqdn" "$port" | ssh_to "$ip" bash
    fi
}

# ----------------------------------------------------------
# Provision + deploy a cloud project; update .env.local
# ----------------------------------------------------------
deploy_cloud_project() {
    local id="$1"
    local provider repo_url type port region auth_key dns_label ip fqdn protocol url
    provider=$(cloud_get "$id" provider)
    repo_url=$(cloud_get "$id" repoUrl)
    type=$(cloud_get "$id" type)
    port=$(cloud_get "$id" port)
    region=$(cloud_get "$id" region)
    auth_key="$(resolve_cloud_path "$(cloud_get "$id" authKey)")"
    dns_label=$(cloud_get "$id" dnsLabel)
    protocol="http"

    # wasm + bucket configured + not --vm  →  use object storage (no VM needed)
    local bucket
    bucket=$(cloud_get "$id" bucket)
    if [ "$type" = "wasm" ] && [ -n "$bucket" ] && [ "$USE_VM" = "false" ]; then
        log "$id: deploying wasm to $provider object storage..."
        deploy_wasm_to_storage "$id"
        return
    fi

    # OCI instances run Oracle Linux 9 with user 'opc'; all others use 'ubuntu'
    SSH_REMOTE_USER="ubuntu"
    [ "$provider" = "oci" ] && SSH_REMOTE_USER="opc"

    log "Provisioning $provider VM for $id in $region..."
    case "$provider" in
        aws)   ip=$(provision_aws   "$id" "$region" "$auth_key" "$port") ;;
        azure) ip=$(provision_azure "$id" "$region" "$auth_key" "$port" "$dns_label") ;;
        gcp)   ip=$(provision_gcp   "$id" "$region" "$auth_key" "$port") ;;
        oci)   ip=$(provision_oci   "$id" "$region" "$auth_key" "$port") ;;
        *)     err "Unknown provider: $provider" ;;
    esac
    save_ip   "$ip"              "$id"
    save_user "$SSH_REMOTE_USER" "$id"

    # Route HTTPS through Caddy: Azure uses DNS label, AWS/GCP/OCI use sslip.io
    if [ -n "$dns_label" ] && [ "$provider" = "azure" ]; then
        fqdn="$ip"
        url="https://$fqdn"
        deploy_to_vm "$id" "$type" "$port" "$repo_url" "$fqdn" "$fqdn"
    elif [ "$provider" = "aws" ] || [ "$provider" = "gcp" ] || [ "$provider" = "oci" ]; then
        fqdn="${ip//./-}.sslip.io"
        url="https://$fqdn"
        deploy_to_vm "$id" "$type" "$port" "$repo_url" "$ip" "$fqdn"
    else
        fqdn=""
        url="${protocol}://${ip}:${port}"
        deploy_to_vm "$id" "$type" "$port" "$repo_url" "$ip"
    fi

    # nextjs: build locally and rsync rather than building on the (small) VM
    [ "$type" = "nextjs" ] && sync_nextjs_build_to_vm "$ip"

    save_host "$url" "$id"
    write_env_url "$id" "$url"
    log "$id → $url (written to .env.local)"
}

# ----------------------------------------------------------
# Return a shell command that exits 0 if the app process is running
# ----------------------------------------------------------
app_running_check() {
    local type="$1"
    case "$type" in
        rails)  echo "systemctl is-active --quiet flowers 2>/dev/null || pgrep -f 'rails server' > /dev/null 2>&1" ;;
        node)   echo "pgrep -f 'node index.js' > /dev/null 2>&1" ;;
        wasm)   echo "pgrep -f 'python3 -m http.server' > /dev/null 2>&1" ;;
        nextjs) echo "pgrep -f 'next' > /dev/null 2>&1" ;;
        *)      echo "false" ;;
    esac
}

# ----------------------------------------------------------
# Lightweight refresh script: git pull + restart only.
# Skips runtime installation (nvm/rbenv/etc.) since those
# are already present from the initial deploy.
# ----------------------------------------------------------
app_refresh_script() {
    local type="$1" clone_url="$2" branch="$3" subdir="$4" port="$5" host_override="${6:-}"
    case "$type" in
        rails)
            cat <<SCRIPT
set -e
# Re-enable swap if it was disabled (e.g. after reboot), or create it if missing.
if [ ! -f /swapfile ]; then
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab > /dev/null
elif ! swapon --show | grep -q /swapfile; then
  sudo swapon /swapfile
fi
# Set up ruby PATH — snap takes priority, fall back to rbenv
if /snap/bin/ruby --version &>/dev/null 2>&1; then
  export PATH="/snap/bin:\$PATH"
elif [ -d "\$HOME/.rbenv" ]; then
  export PATH="\$HOME/.rbenv/bin:\$PATH"
  eval "\$(rbenv init -)"
fi
cd "\$HOME/app"
git pull -q
bundle config set --local path vendor/bundle
bundle install
[ ! -f "\$HOME/.flowers_secret" ] && openssl rand -hex 64 > "\$HOME/.flowers_secret"
RAILS_ENV=production bundle exec rails db:migrate 2>/dev/null || true
RAILS_ENV=production bundle exec rails assets:precompile 2>/dev/null || true
sudo systemctl restart flowers
echo "Flowers restarted on port $port"
SCRIPT
            ;;
        node)
            cat <<SCRIPT
set -e
export NVM_DIR="\$HOME/.nvm"
[ -s "\$NVM_DIR/nvm.sh" ] && . "\$NVM_DIR/nvm.sh"
cd "\$HOME/app"
git pull -q
npm install --silent
pkill -f "node index.js" 2>/dev/null || true; sleep 1
if [ -f run.sh ]; then
  sed -i "s|APP_DIR=.*|APP_DIR=\"\$HOME/app\"|" run.sh
  chmod +x run.sh
  bash run.sh $port || true
  sed -i "s/const host = '[^']*';/const host = '$host_override';/" public/main.js 2>/dev/null || true
  [[ "$host_override" == *.sslip.io ]] && \
    sed -i "s/const port = [0-9]*;/const port = 443;/" public/main.js 2>/dev/null || true
else
  sed -i "s/34\\.57\\.176\\.17/$host_override/g" public/main.js 2>/dev/null || true
  nohup node index.js > "\$HOME/app.log" 2>&1 &
  echo \$! > "\$HOME/app.pid"
fi
echo "Node app restarted on port $port"
SCRIPT
            ;;
        wasm)
            cat <<SCRIPT
set -e
cd "\$HOME/repo"
git pull -q
echo "WASM static files updated (server reads from disk on each request)"
SCRIPT
            ;;
        nextjs)
            cat <<SCRIPT
set -e
export NVM_DIR="\$HOME/.nvm"
[ -s "\$NVM_DIR/nvm.sh" ] && . "\$NVM_DIR/nvm.sh"
cd "\$HOME/app"
git pull -q
npm install --silent
# Build happens locally then gets rsynced — restart follows after sync.
mkdir -p "\$HOME/app/logs"
echo "Portfolio npm install done"
SCRIPT
            ;;
    esac
}

# ----------------------------------------------------------
# Refresh a cloud project in place (SSH + smart checks)
#
# Checks the state of the VM first:
#   app running  → git pull + restart (fast path)
#   app stopped  → full setup (installs runtime, clones, builds)
#   caddy ok     → skip
#   caddy missing/misconfigured → install and configure
# ----------------------------------------------------------
refresh_cloud_project() {
    local id="$1"
    local type repo_url port provider region dns_label ip fqdn
    type=$(cloud_get "$id" type)
    repo_url=$(cloud_get "$id" repoUrl)
    port=$(cloud_get "$id" port)
    provider=$(cloud_get "$id" provider)
    region=$(cloud_get "$id" region)
    dns_label=$(cloud_get "$id" dnsLabel)

    # wasm + bucket configured + not --vm  →  pull latest and re-upload (no VM needed)
    local bucket
    bucket=$(cloud_get "$id" bucket)
    if [ "$type" = "wasm" ] && [ -n "$bucket" ] && [ "$USE_VM" = "false" ]; then
        log "$id: refreshing wasm in $provider object storage (pull + re-upload)..."
        deploy_wasm_to_storage "$id"
        return
    fi

    # OCI instances run Oracle Linux 9 with user 'opc'; all others use 'ubuntu'
    SSH_REMOTE_USER="ubuntu"
    [ "$provider" = "oci" ] && SSH_REMOTE_USER="opc"

    # Reconstruct ip (SSH target) and fqdn (Caddy hostname).
    # For AWS/GCP/OCI: re-query the provider for the *current* public IP rather
    # than trusting the stored host file — the IP changes on every stop/start.
    if [ -n "$dns_label" ] && [ "$provider" = "azure" ]; then
        # Azure DNS label is stable regardless of underlying IP changes.
        fqdn="${dns_label}.${region}.cloudapp.azure.com"
        ip="$fqdn"
    elif [ "$provider" = "aws" ] || [ "$provider" = "gcp" ] || [ "$provider" = "oci" ]; then
        local auth_key current_ip
        auth_key="$(resolve_cloud_path "$(cloud_get "$id" authKey)")"
        log "Looking up current IP for $id from $provider..."
        case "$provider" in
            aws) current_ip=$(provision_aws "$id" "$region" "$auth_key" "$port") ;;
            gcp) current_ip=$(provision_gcp "$id" "$region" "$auth_key" "$port") ;;
            oci) current_ip=$(provision_oci "$id" "$region" "$auth_key" "$port") ;;
        esac
        [ -z "$current_ip" ] && err "Could not retrieve current IP for $id from $provider"
        fqdn="${current_ip//./-}.sslip.io"
        ip="$current_ip"
        # Update stored host file if the IP changed (e.g. after stop/start)
        local new_url="https://$fqdn"
        local old_url
        old_url=$(read_host "$id")
        if [ "$new_url" != "$old_url" ]; then
            log "$id: IP changed (was $old_url, now $new_url) — updating host file"
            save_host "$new_url" "$id"
        fi
    else
        local stored_host
        stored_host=$(read_host "$id")
        [ -z "$stored_host" ] && err "No recorded host for $id. Run a full deploy first."
        ip="${stored_host##*://}"; ip="${ip%%:*}"
        fqdn=""
    fi
    save_ip   "$ip"              "$id"
    save_user "$SSH_REMOTE_USER" "$id"

    wait_for_ssh "$ip"

    # --- Check app process ---
    local app_check app_running
    app_check="$(app_running_check "$type")"
    if ssh_to "$ip" "$app_check" 2>/dev/null; then
        app_running=yes
    else
        app_running=no
    fi
    log "$id: app=$app_running"

    # --- App: fast refresh if running, full setup if not ---
    read -r clone_url branch subdir <<< "$(parse_repo_url "$repo_url")"

    run_full_setup() {
        case "$type" in
            rails)  rails_setup_script  "$clone_url" "$branch" "$subdir" "$port" ;;
            node)   node_setup_script   "$clone_url" "$branch" "$subdir" "$port" "$ip" "${fqdn:-$ip}" ;;
            wasm)   wasm_setup_script   "$clone_url" "$branch" "$subdir" "$port" ;;
            nextjs) nextjs_setup_script "$clone_url" "$branch" "$port" ;;
            *)      err "Unknown project type: $type" ;;
        esac | ssh_to "$ip" bash
    }

    if [ "$app_running" = "yes" ]; then
        log "App is running — refreshing $id (git pull + restart)..."
        if ! app_refresh_script "$type" "$clone_url" "$branch" "$subdir" "$port" "${fqdn:-$ip}" \
            | ssh_to "$ip" bash; then
            warn "$id: fast refresh failed; running full setup..."
            run_full_setup
        fi
    else
        log "App not running — running full setup for $id..."
        run_full_setup
    fi

    # nextjs: build locally and rsync rather than building on the (small) VM
    [ "$type" = "nextjs" ] && sync_nextjs_build_to_vm "$ip"

    # --- Caddy: always reconfigure on refresh ---
    # Never skip: Caddy may be running but without a valid cert (e.g. port 80 was blocked
    # when it first started). Rewriting the Caddyfile and restarting forces a fresh
    # Let's Encrypt issuance attempt with the current hostname.
    if [ -n "$fqdn" ]; then
        log "Reconfiguring Caddy for $fqdn..."
        caddy_setup_script "$fqdn" "$port" | ssh_to "$ip" bash \
            || warn "$id: Caddy setup failed — re-run refresh to retry"
    fi

    # --- Update .env.local from saved host ---
    local url
    url=$(read_host "$id")
    if [ -n "$url" ]; then
        write_env_url "$id" "$url"
    fi

    log "$id refreshed."
}

# ----------------------------------------------------------
# Local project launchers (each saves its PID)
# ----------------------------------------------------------
start_flowers_local() {
    local dir="$PROJECTS_DIR/RubyOnRails/Flowers"
    clone_if_missing "https://github.com/Siderskini/RubyOnRails.git" "RubyOnRails"
    cd "$dir"
    $BUNDLE config set --local path vendor/bundle
    $BUNDLE install --quiet
    $BUNDLE exec rails db:migrate 2>/dev/null || true
    $BUNDLE exec rails db:seed 2>/dev/null || true
    log "Starting Flowers on port 3001..."
    $BUNDLE exec rails server -p 3001 -b 0.0.0.0 > "$LOG_DIR/flowers.log" 2>&1 &
    save_pid $! "flowers"; PIDS+=($!)
    save_host "http://localhost:3001" "flowers"
}

start_labyrinth_local() {
    local dir="$PROJECTS_DIR/Labyrinth"
    clone_if_missing "https://github.com/Siderskini/Labyrinth.git" "Labyrinth"
    cd "$dir"
    npm install --silent
    if [ ! -f key.pem ] || [ ! -f cert.pem ]; then
        log "Generating SSL certs for Labyrinth..."
        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
            -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
    fi
    if grep -q "34.57.176.17" public/main.js 2>/dev/null; then
        log "Patching Labyrinth client IP..."
        sed -i 's/34\.57\.176\.17/localhost/g' public/main.js
    fi
    log "Starting Labyrinth on port 4000..."
    node index.js > "$LOG_DIR/labyrinth.log" 2>&1 &
    save_pid $! "labyrinth"; PIDS+=($!)
    save_host "https://localhost:4000" "labyrinth"
}

start_fishing_local() {
    local dir="$PROJECTS_DIR/LearningGo/fishing/web"
    clone_if_missing "https://github.com/Siderskini/LearningGo.git" "LearningGo"
    cd "$dir"
    log "Starting Fishing on port 8080..."
    python3 -m http.server 8080 > "$LOG_DIR/fishing.log" 2>&1 &
    save_pid $! "fishing"; PIDS+=($!)
    save_host "http://localhost:8080" "fishing"
}

start_portfolio_local() {
    cd "$SCRIPT_DIR"
    npm install --silent
    log "Starting Portfolio on port 3000..."
    npm run dev > "$LOG_DIR/portfolio.log" 2>&1 &
    save_pid $! "portfolio"; PIDS+=($!)
    save_host "http://localhost:3000" "portfolio"
}

clone_if_missing() {
    local url="$1" dir="$2"
    if [ ! -d "$PROJECTS_DIR/$dir" ]; then
        log "Cloning $dir..."
        git clone "$url" "$PROJECTS_DIR/$dir"
    else
        warn "$dir already cloned, skipping."
    fi
}

# ----------------------------------------------------------
# Refresh a single local project
# ----------------------------------------------------------
refresh_local_project() {
    local id="$1"
    kill_project "$id"
    case "$id" in
        flowers)   start_flowers_local ;;
        labyrinth) start_labyrinth_local ;;
        fishing)   start_fishing_local ;;
        portfolio) start_portfolio_local ;;
        *) err "Unknown local project: $id" ;;
    esac
    log "$id refreshed locally."
}

# ----------------------------------------------------------
# Sync .env.local to cloud portfolio VM and restart Next.js
# (no rebuild needed — process.env is read at npm start time)
# ----------------------------------------------------------
sync_urls_to_portfolio_vm() {
    [ ! -f "$SCRIPT_DIR/.env.local" ] && return
    local dns_label region provider port fqdn
    dns_label=$(cloud_get "portfolio" dnsLabel)
    region=$(cloud_get "portfolio" region)
    provider=$(cloud_get "portfolio" provider)
    port=$(cloud_get "portfolio" port)
    [ -z "$dns_label" ] || [ "$provider" != "azure" ] && return
    SSH_REMOTE_USER="ubuntu"
    [ "$provider" = "oci" ] && SSH_REMOTE_USER="opc"
    fqdn="${dns_label}.${region}.cloudapp.azure.com"
    log "Syncing project URLs to portfolio VM ($fqdn)..."
    cat "$SCRIPT_DIR/.env.local" | ssh_to "$fqdn" "cat > \$HOME/app/.env.local"
    ssh_to "$fqdn" "sudo systemctl restart portfolio"
    log "Portfolio restarted with updated project URLs."
}

# ----------------------------------------------------------
# Install a logsync systemd service on the portfolio VM.
# The service SSHes to each cloud project VM every 5 s and writes
# the last 10 lines of ~/app.log to ~/app/logs/{id}.log so that
# the Next.js /api/logs route can serve them locally.
# ----------------------------------------------------------
setup_logsync_on_portfolio_vm() {
    local dns_label region provider fqdn
    dns_label=$(cloud_get "portfolio" dnsLabel)
    region=$(cloud_get "portfolio" region)
    provider=$(cloud_get "portfolio" provider)
    if [ "$provider" != "azure" ] || [ -z "$dns_label" ]; then return; fi
    fqdn="${dns_label}.${region}.cloudapp.azure.com"
    SSH_REMOTE_USER="ubuntu"

    log "Setting up log sync on portfolio VM ($fqdn)..."

    # Deliver the SSH deploy key so the portfolio VM can reach other project VMs
    ssh_to "$fqdn" "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
    scp_to "$SSH_KEY" "ubuntu@${fqdn}:~/.ssh/portfolio_deploy"
    ssh_to "$fqdn" "chmod 600 ~/.ssh/portfolio_deploy"

    # Copy the .ip and .user tracking files for every non-portfolio project
    for ip_file in "$LOG_DIR"/*.ip; do
        [ -f "$ip_file" ] || continue
        local proj_id; proj_id=$(basename "$ip_file" .ip)
        [ "$proj_id" = "portfolio" ] && continue
        scp_to "$ip_file" "ubuntu@${fqdn}:~/app/logs/"
        local user_file="$LOG_DIR/$proj_id.user"
        [ -f "$user_file" ] && scp_to "$user_file" "ubuntu@${fqdn}:~/app/logs/"
    done

    # Write the logsync daemon script
    cat <<'LOGSYNC_SCRIPT' | ssh_to "$fqdn" 'cat > ~/logsync.sh && chmod +x ~/logsync.sh'
#!/bin/bash
# Polls each cloud project VM and writes the last 10 log lines locally.
LOG_DIR="$HOME/app/logs"
SSH_KEY="$HOME/.ssh/portfolio_deploy"

while true; do
    for ip_file in "$LOG_DIR"/*.ip; do
        [ -f "$ip_file" ] || continue
        id="${ip_file##*/}"; id="${id%.ip}"
        ip="$(cat "$ip_file")"
        user="$(cat "$LOG_DIR/$id.user" 2>/dev/null || echo ubuntu)"
        # ControlMaster reuses the existing TCP+crypto connection on every poll
        # after the first handshake, so subsequent calls take <10ms instead of ~300ms.
        ssh -i "$SSH_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=10 \
            -o ControlMaster=auto \
            -o "ControlPath=/tmp/logsync-%r@%h:%p" \
            -o ControlPersist=30 \
            "${user}@${ip}" "tail -10 ~/app.log 2>/dev/null" \
            > "$LOG_DIR/$id.log" 2>/dev/null || true
    done
    sleep 5
done
LOGSYNC_SCRIPT

    # Install and start the systemd service
    ssh_to "$fqdn" bash << 'SETUP_SERVICE'
sudo tee /etc/systemd/system/logsync.service > /dev/null << 'EOF'
[Unit]
Description=Portfolio log sync
After=network.target

[Service]
Type=simple
User=ubuntu
ExecStart=/home/ubuntu/logsync.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable logsync
sudo systemctl restart logsync
SETUP_SERVICE

    log "Log sync service started on portfolio VM"
}

# ----------------------------------------------------------
# Re-sync .ip/.user files and restart the logsync service
# on the portfolio VM (called after --refresh).
# ----------------------------------------------------------
sync_ips_to_portfolio_vm() {
    local dns_label region provider fqdn
    dns_label=$(cloud_get "portfolio" dnsLabel)
    region=$(cloud_get "portfolio" region)
    provider=$(cloud_get "portfolio" provider)
    if [ "$provider" != "azure" ] || [ -z "$dns_label" ]; then return; fi
    fqdn="${dns_label}.${region}.cloudapp.azure.com"
    SSH_REMOTE_USER="ubuntu"

    for ip_file in "$LOG_DIR"/*.ip; do
        [ -f "$ip_file" ] || continue
        local proj_id; proj_id=$(basename "$ip_file" .ip)
        [ "$proj_id" = "portfolio" ] && continue
        scp_to "$ip_file" "ubuntu@${fqdn}:~/app/logs/"
        local user_file="$LOG_DIR/$proj_id.user"
        [ -f "$user_file" ] && scp_to "$user_file" "ubuntu@${fqdn}:~/app/logs/"
    done
    ssh_to "$fqdn" "sudo systemctl restart logsync 2>/dev/null || true"
    log "Log sync IPs updated on portfolio VM"
}

# ----------------------------------------------------------
# --refresh <id> entry point
# ----------------------------------------------------------
if [ -n "$REFRESH_ID" ]; then
    if is_cloud "$REFRESH_ID"; then
        refresh_cloud_project "$REFRESH_ID"
        # Sync updated URLs and (re)install the logsync service on portfolio VM
        sync_urls_to_portfolio_vm
        setup_logsync_on_portfolio_vm
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
# Install/restart the logsync daemon on the portfolio VM
is_cloud "portfolio" && setup_logsync_on_portfolio_vm

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
