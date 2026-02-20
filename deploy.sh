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
CLOUD_CONFIG=""
REFRESH_ID=""
PIDS=()

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[deploy]${NC} $1"; }
warn() { echo -e "${YELLOW}[deploy]${NC} $1"; }
err()  { echo -e "${RED}[deploy]${NC} $1"; exit 1; }

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
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=30 "ubuntu@$ip" "$@"
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
# VM setup scripts sent via SSH for each project type.
# Variables are substituted by the caller before piping to bash.
# ----------------------------------------------------------
rails_setup_script() {
    local clone_url="$1" branch="$2" subdir="$3" port="$4"
    cat <<SCRIPT
set -e
sudo apt-get update -qq
sudo apt-get install -y -qq git curl build-essential libsqlite3-dev libssl-dev zlib1g-dev libyaml-dev

# rbenv + ruby
if [ ! -d "\$HOME/.rbenv" ]; then
  git clone -q https://github.com/rbenv/rbenv.git ~/.rbenv
  git clone -q https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
fi
export PATH="\$HOME/.rbenv/bin:\$PATH"
eval "\$(rbenv init -)"
rbenv install 3.2.3 --skip-existing
rbenv global 3.2.3
gem install bundler --no-document -q 2>/dev/null || true

# Clone or update
if [ -d "\$HOME/app/.git" ]; then
  cd "\$HOME/app" && git pull -q
else
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
bundle install -q
RAILS_ENV=production bundle exec rails db:migrate 2>/dev/null || true
RAILS_ENV=production bundle exec rails db:seed 2>/dev/null || true

# Restart
pkill -f "rails server" 2>/dev/null || true; sleep 1
nohup bundle exec rails server -p $port -b 0.0.0.0 -e production > "\$HOME/app.log" 2>&1 &
echo \$! > "\$HOME/app.pid"
echo "Flowers running on port $port"
SCRIPT
}

node_setup_script() {
    local clone_url="$1" branch="$2" subdir="$3" port="$4" public_ip="$5" host_override="${6:-$5}"
    cat <<SCRIPT
set -e
sudo apt-get update -qq
sudo apt-get install -y -qq git curl openssl

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
sudo apt-get update -qq
sudo apt-get install -y -qq git python3

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
sudo apt-get update -qq
sudo apt-get install -y -qq git curl

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
NODE_OPTIONS=--max-old-space-size=2048 npm run build

# Install systemd service for reliable restarts across reboots and SSH sessions
NODE_BIN="\$(readlink -f "\$(which node)")"
NPM_BIN="\$(readlink -f "\$(which npm)")"
sudo tee /etc/systemd/system/portfolio.service > /dev/null << EOF
[Unit]
Description=Portfolio Next.js
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=\$HOME/app
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
sudo systemctl restart portfolio
echo "Portfolio running on port $port"
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
sudo apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg
curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' -o /tmp/caddy.gpg
sudo rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
sudo gpg --batch --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg /tmp/caddy.gpg
rm -f /tmp/caddy.gpg
curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
    sudo tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq caddy
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
        gcloud compute instances create "$vm_name" \
            --zone="$zone" --machine-type=e2-micro \
            --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
            --tags=portfolio-server \
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
    fi

    gcloud compute instances describe "$vm_name" --zone="$zone" \
        --format="value(networkInterfaces[0].accessConfigs[0].natIP)"
}

provision_oci() {
    local id="$1" region="$2" auth_key="$3" port="$4"
    local vm_name="portfolio-$id"

    # auth_key is a JSON file containing OCI-specific fields alongside the config path.
    # OCI CLI cannot derive compartment/subnet from the config file alone.
    local config_file profile compartment_id subnet_id
    config_file=$(python3  -c "import json; d=json.load(open('$auth_key', encoding='utf-8-sig')); print(d.get('configFile', '$HOME/.oci/config'))")
    profile=$(python3      -c "import json; d=json.load(open('$auth_key', encoding='utf-8-sig')); print(d.get('profile', 'DEFAULT'))")
    compartment_id=$(python3 -c "import json; print(json.load(open('$auth_key', encoding='utf-8-sig'))['compartmentId'])")
    subnet_id=$(python3      -c "import json; print(json.load(open('$auth_key', encoding='utf-8-sig'))['subnetId'])")

    export OCI_CLI_CONFIG_FILE="$config_file"
    local oci_flags="--profile $profile --region $region"

    ensure_ssh_key

    # Find existing instance in any reusable state; create only if none exists
    local instance_id
    instance_id=$(oci compute instance list $oci_flags \
        --compartment-id "$compartment_id" \
        --display-name "$vm_name" \
        --all \
        --query 'data[?"lifecycle-state"!=`TERMINATED`] | sort_by(@,&"time-created")[-1].id' --raw-output 2>/dev/null || echo "")

    if [ -z "$instance_id" ] || [ "$instance_id" = "null" ]; then
        # Resolve latest Ubuntu 22.04 image
        local image_id
        image_id=$(oci compute image list $oci_flags \
            --compartment-id "$compartment_id" \
            --operating-system "Canonical Ubuntu" \
            --operating-system-version "22.04" \
            --shape "VM.Standard.E2.1.Micro" \
            --sort-by TIMECREATED --sort-order DESC \
            --all \
            --query 'data[0].id' --raw-output)
        [ -z "$image_id" ] || [ "$image_id" = "null" ] && \
            err "No Ubuntu 22.04 image found compatible with VM.Standard.E2.1.Micro in compartment $compartment_id"

        # Use first availability domain in the region
        local ad
        ad=$(oci iam availability-domain list $oci_flags \
            --compartment-id "$compartment_id" \
            --query 'data[0].name' --raw-output)

        log "Launching OCI instance $vm_name in $ad..."
        instance_id=$(oci compute instance launch $oci_flags \
            --compartment-id "$compartment_id" \
            --display-name "$vm_name" \
            --availability-domain "$ad" \
            --shape "VM.Standard.E2.1.Micro" \
            --image-id "$image_id" \
            --subnet-id "$subnet_id" \
            --assign-public-ip true \
            --ssh-authorized-keys-file "${SSH_KEY}.pub" \
            --wait-for-state RUNNING \
            --query 'data.id' --raw-output)
        sleep 20  # allow SSH daemon to start
    else
        local state
        state=$(oci compute instance get $oci_flags \
            --instance-id "$instance_id" \
            --query 'data."lifecycle-state"' --raw-output 2>/dev/null || echo "")
        case "$state" in
            RUNNING) ;;
            STOPPED)
                log "Starting stopped OCI instance $vm_name..."
                oci compute instance action $oci_flags \
                    --instance-id "$instance_id" \
                    --action START \
                    --wait-for-state RUNNING > /dev/null
                sleep 20
                ;;
            STOPPING)
                log "Waiting for OCI instance $vm_name to stop before restart..."
                oci compute instance get $oci_flags \
                    --instance-id "$instance_id" \
                    --wait-for-state STOPPED \
                    --max-wait-seconds 600 > /dev/null
                oci compute instance action $oci_flags \
                    --instance-id "$instance_id" \
                    --action START \
                    --wait-for-state RUNNING > /dev/null
                sleep 20
                ;;
            PROVISIONING|STARTING)
                log "Waiting for OCI instance $vm_name to become RUNNING..."
                oci compute instance get $oci_flags \
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

    oci compute instance list-vnics $oci_flags \
        --instance-id "$instance_id" \
        --query 'data[0]."public-ip"' --raw-output
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
    auth_key="$(resolve_cloud_path "$(cloud_get "$id" authKey")")"
    dns_label=$(cloud_get "$id" dnsLabel)
    protocol="http"

    log "Provisioning $provider VM for $id in $region..."
    case "$provider" in
        aws)   ip=$(provision_aws   "$id" "$region" "$auth_key" "$port") ;;
        azure) ip=$(provision_azure "$id" "$region" "$auth_key" "$port" "$dns_label") ;;
        gcp)   ip=$(provision_gcp   "$id" "$region" "$auth_key" "$port") ;;
        oci)   ip=$(provision_oci   "$id" "$region" "$auth_key" "$port") ;;
        *)     err "Unknown provider: $provider" ;;
    esac

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
        rails)  echo "pgrep -f 'rails server' > /dev/null 2>&1" ;;
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
export PATH="\$HOME/.rbenv/bin:\$PATH"
eval "\$(rbenv init -)"
cd "\$HOME/app"
git pull -q
bundle config set --local path vendor/bundle
bundle install -q
RAILS_ENV=production bundle exec rails db:migrate 2>/dev/null || true
pkill -f "rails server" 2>/dev/null || true; sleep 1
nohup bundle exec rails server -p $port -b 0.0.0.0 -e production > "\$HOME/app.log" 2>&1 &
echo \$! > "\$HOME/app.pid"
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
# Re-enable swap if it was disabled (e.g. after a VM reboot)
if ! swapon --show | grep -q /swapfile; then sudo swapon /swapfile 2>/dev/null || true; fi
NODE_OPTIONS=--max-old-space-size=2048 npm run build
mkdir -p "\$HOME/app/logs"
sudo systemctl restart portfolio
echo "Portfolio restarted on port $port"
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

    # Reconstruct ip (SSH target) and fqdn (Caddy hostname).
    # For AWS/GCP/OCI: re-query the provider for the *current* public IP rather
    # than trusting the stored host file — the IP changes on every stop/start.
    if [ -n "$dns_label" ] && [ "$provider" = "azure" ]; then
        # Azure DNS label is stable regardless of underlying IP changes.
        fqdn="${dns_label}.${region}.cloudapp.azure.com"
        ip="$fqdn"
    elif [ "$provider" = "aws" ] || [ "$provider" = "gcp" ] || [ "$provider" = "oci" ]; then
        local auth_key current_ip
        auth_key="$(resolve_cloud_path "$(cloud_get "$id" authKey")")"
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
    if [ "$app_running" = "yes" ]; then
        log "App is running — refreshing $id (git pull + restart)..."
        app_refresh_script "$type" "$clone_url" "$branch" "$subdir" "$port" "${fqdn:-$ip}" \
            | ssh_to "$ip" bash
    else
        log "App not running — running full setup for $id..."
        case "$type" in
            rails)  rails_setup_script  "$clone_url" "$branch" "$subdir" "$port" ;;
            node)   node_setup_script   "$clone_url" "$branch" "$subdir" "$port" "$ip" "${fqdn:-$ip}" ;;
            wasm)   wasm_setup_script   "$clone_url" "$branch" "$subdir" "$port" ;;
            nextjs) nextjs_setup_script "$clone_url" "$branch" "$port" ;;
        esac | ssh_to "$ip" bash
    fi

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
    fqdn="${dns_label}.${region}.cloudapp.azure.com"
    log "Syncing project URLs to portfolio VM ($fqdn)..."
    cat "$SCRIPT_DIR/.env.local" | ssh_to "$fqdn" "cat > \$HOME/app/.env.local"
    ssh_to "$fqdn" "sudo systemctl restart portfolio"
    log "Portfolio restarted with updated project URLs."
}

# ----------------------------------------------------------
# --refresh <id> entry point
# ----------------------------------------------------------
if [ -n "$REFRESH_ID" ]; then
    if is_cloud "$REFRESH_ID"; then
        refresh_cloud_project "$REFRESH_ID"
        # Sync updated URLs to portfolio VM after refreshing any cloud project
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
