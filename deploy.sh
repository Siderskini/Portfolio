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

# Remove /usr/local/bin from PATH — broken bundle shebang lives there.
export PATH="${PATH//:\/usr\/local\/bin/}"
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
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cloud)    CLOUD_CONFIG="$(realpath "$2")"; shift 2 ;;
        --refresh)  REFRESH_ID="$2";                shift 2 ;;
        *)          err "Unknown argument: $1" ;;
    esac
done

mkdir -p "$PROJECTS_DIR" "$LOG_DIR"

# ----------------------------------------------------------
# Cloud config helpers (python3 for JSON parsing)
# ----------------------------------------------------------
cloud_get() {
    local id="$1" field="$2"
    [ -z "$CLOUD_CONFIG" ] || [ ! -f "$CLOUD_CONFIG" ] && echo "" && return
    python3 -c "
import json
d = json.load(open('$CLOUD_CONFIG'))
print(d.get('$id', {}).get('$field', ''))
" 2>/dev/null || echo ""
}

cloud_ids() {
    [ -z "$CLOUD_CONFIG" ] || [ ! -f "$CLOUD_CONFIG" ] && echo "" && return
    python3 -c "
import json
print(' '.join(json.load(open('$CLOUD_CONFIG')).keys()))
" 2>/dev/null || echo ""
}

is_cloud() { [ -n "$(cloud_get "$1" provider)" ]; }

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
    echo ""
    log "Shutting down local services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

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
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=30 "ubuntu@$ip" "$@"
}

scp_to() {
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$@"
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
  git clone -q --branch $branch $clone_url "\$HOME/repo"
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
    local clone_url="$1" branch="$2" subdir="$3" port="$4" public_ip="$5"
    cat <<SCRIPT
set -e
sudo apt-get update -qq
sudo apt-get install -y -qq git curl openssl

# Node.js via nvm
if [ ! -d "\$HOME/.nvm" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash -q
fi
export NVM_DIR="\$HOME/.nvm"
[ -s "\$NVM_DIR/nvm.sh" ] && . "\$NVM_DIR/nvm.sh"
nvm install --lts --silent

# Clone or update
if [ -d "\$HOME/app/.git" ]; then
  cd "\$HOME/app" && git pull -q
else
  git clone -q --branch $branch $clone_url "\$HOME/app"
fi

cd "\$HOME/app"
npm install --silent

# SSL certs
if [ ! -f key.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=$public_ip" 2>/dev/null
fi

# Patch hardcoded IP to this VM's public IP
sed -i "s/34\\.57\\.176\\.17/$public_ip/g" public/main.js 2>/dev/null || true

# Restart
pkill -f "node index.js" 2>/dev/null || true; sleep 1
nohup node index.js > "\$HOME/app.log" 2>&1 &
echo \$! > "\$HOME/app.pid"
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
  git clone -q --branch $branch $clone_url "\$HOME/repo"
fi

cd "\$HOME/repo/$subdir"

# Restart
pkill -f "python3 -m http.server" 2>/dev/null || true; sleep 1
nohup python3 -m http.server $port > "\$HOME/app.log" 2>&1 &
echo \$! > "\$HOME/app.pid"
echo "Fishing running on port $port"
SCRIPT
}

# ----------------------------------------------------------
# Cloud providers — each returns the VM's public IP via stdout
# ----------------------------------------------------------

provision_aws() {
    local id="$1" region="$2" auth_key="$3" port="$4"
    export AWS_SHARED_CREDENTIALS_FILE="$auth_key"
    local vm_name="portfolio-$id"
    local sg_name="portfolio-${id}-sg"

    ensure_ssh_key

    # Import SSH key pair if not present
    aws ec2 describe-key-pairs --key-names "portfolio-deploy" --region "$region" &>/dev/null || \
        aws ec2 import-key-pair \
            --key-name "portfolio-deploy" \
            --public-key-material "fileb://${SSH_KEY}.pub" \
            --region "$region" --output none

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
        aws ec2 authorize-security-group-ingress --group-id "$sg_id" --protocol tcp --port 22   --cidr 0.0.0.0/0 --region "$region" --output none
        aws ec2 authorize-security-group-ingress --group-id "$sg_id" --protocol tcp --port "$port" --cidr 0.0.0.0/0 --region "$region" --output none
    fi

    # Find or create instance
    local instance_id
    instance_id=$(aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=$vm_name" "Name=instance-state-name,Values=running,pending" \
        --query "Reservations[0].Instances[0].InstanceId" --output text --region "$region")
    if [ "$instance_id" = "None" ] || [ -z "$instance_id" ]; then
        local ami
        ami=$(aws ec2 describe-images \
            --owners 099720109477 \
            --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
                      "Name=state,Values=available" \
            --query "sort_by(Images,&CreationDate)[-1].ImageId" \
            --output text --region "$region")
        instance_id=$(aws ec2 run-instances \
            --image-id "$ami" --instance-type t2.micro \
            --key-name "portfolio-deploy" \
            --security-group-ids "$sg_id" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$vm_name}]" \
            --query "Instances[0].InstanceId" --output text --region "$region")
        log "Waiting for EC2 instance $instance_id to start..."
        aws ec2 wait instance-running --instance-ids "$instance_id" --region "$region"
        sleep 15  # allow SSH daemon to start
    fi

    aws ec2 describe-instances \
        --instance-ids "$instance_id" \
        --query "Reservations[0].Instances[0].PublicIpAddress" \
        --output text --region "$region"
}

provision_azure() {
    local id="$1" region="$2" auth_key="$3" port="$4"
    local rg="portfolio-rg"
    local vm_name="portfolio-$id"

    ensure_ssh_key
    az login --service-principal --json-auth "$auth_key" --output none

    az group create --name "$rg" --location "$region" --output none 2>/dev/null || true

    local state
    state=$(az vm show --name "$vm_name" --resource-group "$rg" \
        --query "provisioningState" -o tsv 2>/dev/null || echo "")
    if [ -z "$state" ]; then
        az vm create \
            --name "$vm_name" --resource-group "$rg" \
            --image Ubuntu2204 --size Standard_B1s \
            --admin-username ubuntu \
            --ssh-key-values "${SSH_KEY}.pub" \
            --output none
        az vm open-port --name "$vm_name" --resource-group "$rg" --port "$port" --priority 900 --output none
        sleep 15
    fi

    az vm show --name "$vm_name" --resource-group "$rg" \
        --show-details --query "publicIps" -o tsv
}

provision_gcp() {
    local id="$1" region="$2" auth_key="$3" port="$4"
    local zone="${region}-a"
    local vm_name="portfolio-$id"
    local gcp_project
    gcp_project=$(python3 -c "import json; print(json.load(open('$auth_key'))['project_id'])")

    ensure_ssh_key
    gcloud auth activate-service-account --key-file="$auth_key" --quiet
    gcloud config set project "$gcp_project" --quiet

    # Firewall rule
    gcloud compute firewall-rules describe "portfolio-app" --quiet &>/dev/null || \
        gcloud compute firewall-rules create "portfolio-app" \
            --allow "tcp:$port" --target-tags portfolio-server --quiet 2>/dev/null || true

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
        sleep 20
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
    config_file=$(python3  -c "import json; d=json.load(open('$auth_key')); print(d.get('configFile', '$HOME/.oci/config'))")
    profile=$(python3      -c "import json; d=json.load(open('$auth_key')); print(d.get('profile', 'DEFAULT'))")
    compartment_id=$(python3 -c "import json; print(json.load(open('$auth_key'))['compartmentId'])")
    subnet_id=$(python3      -c "import json; print(json.load(open('$auth_key'))['subnetId'])")

    export OCI_CLI_CONFIG_FILE="$config_file"
    local oci_flags="--profile $profile --region $region"

    ensure_ssh_key

    # Find existing running instance
    local instance_id
    instance_id=$(oci compute instance list $oci_flags \
        --compartment-id "$compartment_id" \
        --display-name "$vm_name" \
        --lifecycle-state RUNNING \
        --query 'data[0].id' --raw-output 2>/dev/null || echo "")

    if [ -z "$instance_id" ] || [ "$instance_id" = "null" ]; then
        # Resolve latest Ubuntu 22.04 image
        local image_id
        image_id=$(oci compute image list $oci_flags \
            --compartment-id "$compartment_id" \
            --operating-system "Canonical Ubuntu" \
            --operating-system-version "22.04" \
            --sort-by TIMECREATED --sort-order DESC \
            --limit 1 \
            --query 'data[0].id' --raw-output)

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
    fi

    oci compute instance list-vnics $oci_flags \
        --instance-id "$instance_id" \
        --query 'data[0]."public-ip"' --raw-output
}

# ----------------------------------------------------------
# Deploy a project to a provisioned VM
# ----------------------------------------------------------
deploy_to_vm() {
    local id="$1" type="$2" port="$3" repo_url="$4" ip="$5"
    read -r clone_url branch subdir <<< "$(parse_repo_url "$repo_url")"

    log "Deploying $id to $ip (type=$type, port=$port)..."
    case "$type" in
        rails) rails_setup_script "$clone_url" "$branch" "$subdir" "$port" ;;
        node)  node_setup_script  "$clone_url" "$branch" "$subdir" "$port" "$ip" ;;
        wasm)  wasm_setup_script  "$clone_url" "$branch" "$subdir" "$port" ;;
        *)     err "Unknown project type: $type" ;;
    esac | ssh_to "$ip" bash
}

# ----------------------------------------------------------
# Provision + deploy a cloud project; update .env.local
# ----------------------------------------------------------
deploy_cloud_project() {
    local id="$1"
    local provider repo_url type port region auth_key ip protocol
    provider=$(cloud_get "$id" provider)
    repo_url=$(cloud_get "$id" repoUrl)
    type=$(cloud_get "$id" type)
    port=$(cloud_get "$id" port)
    region=$(cloud_get "$id" region)
    auth_key=$(cloud_get "$id" authKey)
    protocol="http"
    [ "$type" = "node" ] && protocol="https"

    log "Provisioning $provider VM for $id in $region..."
    case "$provider" in
        aws)   ip=$(provision_aws   "$id" "$region" "$auth_key" "$port") ;;
        azure) ip=$(provision_azure "$id" "$region" "$auth_key" "$port") ;;
        gcp)   ip=$(provision_gcp   "$id" "$region" "$auth_key" "$port") ;;
        oci)   ip=$(provision_oci   "$id" "$region" "$auth_key" "$port") ;;
        *)     err "Unknown provider: $provider" ;;
    esac

    deploy_to_vm "$id" "$type" "$port" "$repo_url" "$ip"
    save_host "$protocol://$ip:$port" "$id"

    # Write cloud URL to .env.local so portfolio picks it up
    local env_key
    env_key="$(echo "$id" | tr '[:lower:]' '[:upper:]' | tr '-' '_')_URL"
    local env_file="$SCRIPT_DIR/.env.local"
    touch "$env_file"
    # Remove existing entry then append
    sed -i "/^${env_key}=/d" "$env_file"
    echo "${env_key}=${protocol}://${ip}:${port}" >> "$env_file"
    log "$id → ${protocol}://${ip}:${port} (written to .env.local)"
}

# ----------------------------------------------------------
# Refresh a cloud project in place (SSH + restart)
# ----------------------------------------------------------
refresh_cloud_project() {
    local id="$1"
    local host
    host=$(read_host "$id")
    [ -z "$host" ] && err "No recorded host for $id. Run a full deploy first."
    local ip="${host##*://}"; ip="${ip%%:*}"

    local type repo_url port
    type=$(cloud_get "$id" type)
    repo_url=$(cloud_get "$id" repoUrl)
    port=$(cloud_get "$id" port)

    log "Refreshing $id on $ip..."
    deploy_to_vm "$id" "$type" "$port" "$repo_url" "$ip"
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
# --refresh <id> entry point
# ----------------------------------------------------------
if [ -n "$REFRESH_ID" ]; then
    if is_cloud "$REFRESH_ID"; then
        refresh_cloud_project "$REFRESH_ID"
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

start_portfolio_local

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
