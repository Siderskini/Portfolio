#!/bin/bash
# Object storage upload functions for wasm projects.
# Each upload_wasm_* function uploads a local directory to a provider bucket,
# sets the correct Content-Type per file, and prints the public index.html URL.
# Sourced by deploy.sh; references LOG_DIR, SCRIPT_DIR from the calling shell.

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
    namespace=$(oci os ns get "${oci_flags[@]}" 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('data',''))" 2>/dev/null)
    [ -z "$namespace" ] && err "$id: failed to retrieve OCI Object Storage namespace. Check oci-credentials.json and that profile '$profile' exists in '$config_file'."

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
# Used for type=wasm projects with a bucket field in cloud.json.
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
