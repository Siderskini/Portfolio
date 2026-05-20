#!/bin/bash
# High-level cloud orchestration: deploy, refresh, and URL sync.
# Sourced by deploy.sh; calls into providers.sh and storage.sh.

# ----------------------------------------------------------
# Ansible helpers
# ----------------------------------------------------------
write_ansible_inventory() {
    local ip="$1" user="$2"
    mkdir -p "$SCRIPT_DIR/ansible/inventory"
    cat > "$SCRIPT_DIR/ansible/inventory/current.ini" <<EOF
[vm]
$ip ansible_user=$user ansible_ssh_private_key_file=$SSH_KEY
EOF
}

run_ansible() {
    local playbook="$1"; shift
    ANSIBLE_CONFIG="$SCRIPT_DIR/ansible/ansible.cfg" \
    ansible-playbook \
        -i "$SCRIPT_DIR/ansible/inventory/current.ini" \
        "$SCRIPT_DIR/ansible/playbooks/$playbook" \
        "$@"
}

# ----------------------------------------------------------
# Deploy a project to a provisioned VM via Ansible
# ----------------------------------------------------------
deploy_to_vm() {
    local id="$1" type="$2" port="$3" repo_url="$4" ip="$5" fqdn="${6:-}"
    read -r clone_url branch subdir <<< "$(parse_repo_url "$repo_url")"
    local host_override="${fqdn:-$ip}"

    wait_for_ssh "$ip"
    write_ansible_inventory "$ip" "$SSH_REMOTE_USER"
    log "Deploying $id to $ip via Ansible (type=$type, port=$port)..."
    run_ansible setup.yml \
        -e "type=$type" \
        -e "port=$port" \
        -e "clone_url=$clone_url" \
        -e "branch=$branch" \
        -e "subdir=$subdir" \
        -e "fqdn=$fqdn" \
        -e "host_override=$host_override" \
        -e "project_id=$id"
}

# ----------------------------------------------------------
# Build portfolio locally and rsync .next to the VM.
# The VM never builds — too small. Service is started after the push.
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
# Refresh a cloud project in place (Ansible idempotent refresh).
# Runs refresh.yml (git pull + restart); falls back to full setup.yml on failure.
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

    read -r clone_url branch subdir <<< "$(parse_repo_url "$repo_url")"
    local host_override="${fqdn:-$ip}"

    wait_for_ssh "$ip"
    write_ansible_inventory "$ip" "$SSH_REMOTE_USER"

    local extra_vars=(
        -e "type=$type"
        -e "port=$port"
        -e "clone_url=$clone_url"
        -e "branch=$branch"
        -e "subdir=$subdir"
        -e "fqdn=$fqdn"
        -e "host_override=$host_override"
        -e "project_id=$id"
    )

    if ! run_ansible refresh.yml "${extra_vars[@]}"; then
        warn "$id: refresh failed — running full setup..."
        run_ansible setup.yml "${extra_vars[@]}"
    fi

    # nextjs: build locally and rsync rather than building on the (small) VM
    [ "$type" = "nextjs" ] && sync_nextjs_build_to_vm "$ip"

    local url
    url=$(read_host "$id")
    if [ -n "$url" ]; then
        write_env_url "$id" "$url"
    fi

    log "$id refreshed."
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
    fqdn="${dns_label}.${region}.cloudapp.azure.com"
    log "Syncing project URLs to portfolio VM ($fqdn)..."
    cat "$SCRIPT_DIR/.env.local" | ssh_to "$fqdn" "cat > \$HOME/app/.env.local"
    ssh_to "$fqdn" "sudo systemctl restart portfolio"
    log "Portfolio restarted with updated project URLs."
}
