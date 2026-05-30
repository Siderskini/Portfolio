# Deploying to Azure

The deploy script provisions an Azure VM, deploys the portfolio (or any project) to it, and serves it over **HTTPS via an Azure DNS label + Caddy** — no domain purchase required.

For wasm projects, you can instead deploy to Azure Blob Storage — no VM needed. See the [Wasm Object Storage](#wasm-object-storage-blob-storage) section below.

---

## How HTTPS Works Without a Domain

Azure assigns a free, stable DNS hostname to any public IP:

```
<label>.<region>.cloudapp.azure.com
```

The deploy script:
1. Creates the VM with the DNS label attached to its public IP
2. Opens ports 80 and 443
3. Installs [Caddy](https://caddyserver.com/) on the VM
4. Configures Caddy to listen on `<label>.<region>.cloudapp.azure.com`
5. Caddy automatically obtains a Let's Encrypt certificate
6. Caddy reverse-proxies HTTPS traffic to your app

**Port 80 must remain open** — Let's Encrypt's HTTP-01 challenge requires it.

---

## VM Details

| Property | Value |
|---|---|
| Default VM size | `Standard_DS1_v2` |
| OS | Ubuntu 22.04 LTS |
| Resource group | `portfolio-rg` |
| VM name | `portfolio-<id>` |
| SSH key | `~/.ssh/portfolio_deploy` (4096-bit RSA, auto-generated) |
| SSH user | `ubuntu` |

---

## Step 1 — Install the Azure CLI

```bash
# macOS
brew install azure-cli

# Ubuntu/Debian
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

Verify: `az --version`

Log in once interactively to bootstrap your session:

```bash
az login
```

---

## Step 2 — Create a Service Principal

```bash
az ad sp create-for-rbac \
  --name "portfolio-deploy" \
  --role Contributor \
  --scopes /subscriptions/<your-subscription-id> \
  --sdk-auth \
  > azure-sp.json
```

Find your subscription ID:

```bash
az account list --output table
```

The `--sdk-auth` flag produces the format the deploy script expects:

```json
{
  "clientId":       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret":   "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "tenantId":       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

The deploy script also handles the standard SP format using `appId` / `password` / `tenant` field names.

> **If you see "No subscriptions found":** Assign the Contributor role manually:
> ```bash
> az role assignment create \
>   --assignee <clientId> \
>   --role Contributor \
>   --scope /subscriptions/<your-subscription-id>
> ```

> **Security:** `azure-sp.json` is listed in `.gitignore` and must never be committed.

---

## Step 3 — Add an Entry to `cloud.json`

```bash
cp cloud.json.template cloud.json
```

### Deploying the Portfolio (Next.js with HTTPS)

```json
{
  "portfolio": {
    "repoUrl": "https://github.com/Siderskini/Portfolio",
    "type": "nextjs",
    "port": 3000,
    "provider": "azure",
    "region": "westus2",
    "authKey": "./azure-sp.json",
    "dnsLabel": "sidd-portfolio",
    "vmSize": "Standard_DS1_v2"
  }
}
```

The resulting HTTPS URL: `https://sidd-portfolio.westus2.cloudapp.azure.com`

**DNS label uniqueness:** Azure DNS labels must be globally unique within a region across all Azure customers. If your chosen label is taken, add a year or random suffix (e.g. `sidd-portfolio-2026`).

> **How Next.js deploy works:** The Next.js build runs locally on your machine (`npm run build`), then the `.next/` directory is rsynced to the VM. The VM never runs the build — it's too small. The portfolio systemd service is started after the sync completes.

### Deploying Any Other Project

```json
{
  "flowers": {
    "repoUrl": "https://github.com/Siderskini/RubyOnRails/tree/main/Flowers",
    "type": "rails",
    "port": 3001,
    "provider": "azure",
    "region": "westus2",
    "authKey": "./azure-sp.json"
  }
}
```

Without a `dnsLabel`, the app port is exposed directly as `http://<public-ip>:<port>` (no Caddy, no HTTPS).

### Fields

| Field | Description |
|---|---|
| `repoUrl` | GitHub repo URL. Use `/tree/branch/subdir` for a subdirectory. |
| `type` | `rails`, `node`, `wasm`, or `nextjs` |
| `port` | Internal port the app listens on |
| `provider` | `azure` |
| `region` | Azure region (e.g. `westus2`, `eastus`, `westeurope`) |
| `authKey` | Relative or absolute path to your `azure-sp.json` |
| `dnsLabel` | *(Optional)* DNS label for HTTPS. Required for `nextjs` and recommended for all others. |
| `vmSize` | *(Optional)* Azure VM size. Defaults to `Standard_DS1_v2`. |

### VM Sizes

| Size | vCPU | RAM | Notes |
|---|---|---|---|
| `Standard_DS1_v2` | 1 | 3.5 GB | Default — reliable across most regions |
| `Standard_B2s` | 2 | 4 GB | Good balance if DS1_v2 is unavailable |
| `Standard_B1s` | 1 | 1 GB | Cheapest — may be unavailable in some regions |

If you get `SkuNotAvailable`, try a different `vmSize` or `region`.

---

## Step 4 — Make Sure the Repo is Public

The Azure VM clones the portfolio repo directly from GitHub. The repo must be publicly accessible.

---

## Step 5 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

The script will:

1. Log in to Azure with the service principal
2. Create resource group `portfolio-rg` in your region (idempotent)
3. Create VM `portfolio-<id>` with the DNS label attached to its public IP (or reuse/start an existing one)
4. For existing VMs: sync the current SSH public key using `az vm user update` — prevents lockout after key rotation
5. Open ports 80 and 443
6. Wait for SSH readiness
7. Run an Ansible playbook: install Node via nvm, clone the repo, start the app as a systemd service
8. Install Caddy, write Caddyfile pointing to `localhost:<port>`
9. Caddy obtains a Let's Encrypt cert for `<label>.<region>.cloudapp.azure.com`
10. For `nextjs`: build the portfolio locally, rsync `.next/` to the VM, start the service
11. Write the HTTPS URL to `.env.local`

Re-running deploy never creates a duplicate VM — VMs are found by name in the resource group.

---

## Wasm Object Storage (Blob Storage)

For `type: "wasm"` projects, adding `bucket` and `storageAccount` fields deploys to Azure Blob Storage instead of a VM:

```json
{
  "fishing": {
    "repoUrl": "https://github.com/Siderskini/LearningGo/tree/main/fishing/web",
    "type": "wasm",
    "provider": "azure",
    "region": "eastus",
    "authKey": "./azure-sp.json",
    "bucket": "wasm",
    "storageAccount": "myportfoliostorage"
  }
}
```

`storageAccount` must be globally unique, lowercase, and ≤24 characters. The storage account and container are created automatically if they don't exist.

---

## What URL to Use

After deploy, the console prints:

```
[deploy]  portfolio    https://sidd-portfolio.westus2.cloudapp.azure.com
```

Navigate to that URL in any browser. The certificate is trusted — no browser warning.

---

## How Project URLs Flow to the Portfolio

When any cloud project is deployed or refreshed, its URL is written to `.env.local`. The deploy script then uploads `.env.local` to the portfolio VM and restarts `npm start` — no rebuild needed. The portfolio VM never SSHes back to any project VM; all communication is one-directional from the local deploy machine.

---

## Refreshing (Pull Latest Code + Restart)

```bash
./deploy.sh --cloud cloud.json --refresh portfolio
```

For VM projects: SSHes in, runs `git pull`, and restarts the service via Ansible. Caddy is not reinstalled — the existing certificate remains valid.

For `nextjs`: also rebuilds locally and rsyncs the new `.next/` to the VM.

For wasm+Blob: re-clones/pulls locally and re-uploads all files.

---

## Troubleshooting

**"No subscriptions found for this service principal"**
The SP was created without a role assignment. See Step 2 — assign Contributor on your subscription.

**`SkuNotAvailable` for a VM size**
Change `vmSize` in `cloud.json` or pick a different `region`.

**SSH "Permission denied (publickey)"**
The SSH key on the VM is out of date. Run:
```bash
az login --service-principal --username <clientId> --password <clientSecret> --tenant <tenantId>
az vm user update --resource-group portfolio-rg --name portfolio-<id> \
  --username ubuntu --ssh-key-value "$(cat ~/.ssh/portfolio_deploy.pub)"
```
Then retry the deploy.

**VM created but app never started**
Re-run:
```bash
./deploy.sh --cloud cloud.json --refresh portfolio
```

**Next.js build killed (SIGKILL)**
The build ran out of memory. Use `Standard_B2s` or larger. The Next.js build runs locally (not on the VM), so this should not normally happen — if it does, check your local machine's available memory.

**Caddy: "failed to obtain certificate"**
Port 80 must be publicly reachable for the HTTP-01 challenge. On the VM: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.

**Portfolio still shows `localhost` URLs**
`.env.local` is read at `npm start` time. After any cloud project is deployed, the script automatically calls `sync_urls_to_portfolio_vm`. If that step was skipped, run:
```bash
./deploy.sh --cloud cloud.json --refresh portfolio
```
