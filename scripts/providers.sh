#!/bin/bash
# Cloud provider VM provisioning: AWS, Azure, GCP, OCI.
# Each function provisions (or reuses) a VM and prints its public IP to stdout.
# Sourced by deploy.sh; references SSH_KEY, SSH_REMOTE_USER from the calling shell.

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

    # Always sync the key pair so local private key and AWS public key stay in step.
    aws ec2 delete-key-pair --key-name "portfolio-deploy" --region "$region" --output text > /dev/null 2>&1 || true
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
        # Sync current local public key so key rotation never locks us out
        log "Syncing SSH public key to $vm_name..."
        az vm user update \
            --resource-group "$rg" \
            --name "$vm_name" \
            --username ubuntu \
            --ssh-key-value "$(cat "${SSH_KEY}.pub")" \
            --output none
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
