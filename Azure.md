# Deploying to Azure

The deploy script can provision an Azure VM, deploy the portfolio (or any project) to it, and serve it over **HTTPS via an Azure DNS label + Caddy** — no domain purchase required.

---

## How HTTPS Works Without a Domain

Azure assigns a free, stable DNS hostname to any public IP:

```
<label>.<region>.cloudapp.azure.com
```

For example: `sidd-portfolio.westus2.cloudapp.azure.com`

The deploy script:
1. Creates the VM with the DNS label attached to its public IP
2. Opens ports 80 and 443 on the VM
3. Installs [Caddy](https://caddyserver.com/) on the VM
4. Configures Caddy to listen on `<label>.<region>.cloudapp.azure.com`
5. Caddy automatically obtains a Let's Encrypt certificate for that hostname
6. Caddy reverse-proxies HTTPS traffic to the Next.js process on its internal port

**Port 80 must remain open** — Let's Encrypt's HTTP-01 challenge requires it.

---

## Step 1 — Install the Azure CLI

```bash
# macOS
brew install azure-cli

# Ubuntu/Debian
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Or download from:
# https://learn.microsoft.com/en-us/cli/azure/install-azure-cli
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

Replace `<your-subscription-id>` with your subscription ID. Find it with:

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

The deploy script also handles the standard (non-`--sdk-auth`) format using `appId` / `password` / `tenant` field names.

> **If you see "No subscriptions found":** The service principal was created without the `--scopes` flag. Assign the Contributor role manually:
> ```bash
> az role assignment create \
>   --assignee <clientId> \
>   --role Contributor \
>   --scope /subscriptions/<your-subscription-id>
> ```

> **Security:** `azure-sp.json` is listed in `.gitignore` and must never be committed.

---

## Step 3 — Add an Entry to `cloud.json`

Copy `cloud.json.template` to `cloud.json` if you haven't already:

```bash
cp cloud.json.template cloud.json
```

### Deploying the Portfolio

```json
{
  "portfolio": {
    "repoUrl": "https://github.com/Siderskini/Portfolio",
    "type": "nextjs",
    "port": 3000,
    "provider": "azure",
    "region": "westus2",
    "authKey": "/home/you/azure-sp.json",
    "dnsLabel": "sidd-portfolio",
    "vmSize": "Standard_DS1_v2"
  }
}
```

The resulting HTTPS URL: `https://sidd-portfolio.westus2.cloudapp.azure.com`

### Deploying Any Other Project

```json
{
  "flowers": {
    "repoUrl": "https://github.com/Siderskini/RubyOnRails/tree/main/Flowers",
    "type": "rails",
    "port": 3001,
    "provider": "azure",
    "region": "westus2",
    "authKey": "/home/you/azure-sp.json"
  }
}
```

Without a `dnsLabel`, the script opens the app port directly and exposes it as `http://<public-ip>:<port>`.

### Fields

| Field | Description |
|---|---|
| `repoUrl` | GitHub repo URL. Use `/tree/branch/subdir` for a subdirectory. |
| `type` | `rails`, `node`, `wasm`, or `nextjs` |
| `port` | Internal port the app listens on |
| `provider` | `azure` |
| `region` | Azure region (e.g. `westus2`, `eastus`, `westeurope`) |
| `authKey` | Absolute or relative path to your `azure-sp.json` |
| `dnsLabel` | *(Optional)* DNS label for `<label>.<region>.cloudapp.azure.com`. Required for HTTPS. |
| `vmSize` | *(Optional)* Azure VM size. Defaults to `Standard_DS1_v2`. |

### DNS Label Uniqueness

Azure DNS labels must be **globally unique within a region** across all Azure customers. If `sidd-portfolio` is taken, choose a different label (e.g. `sidd-portfolio-2026`). The deploy fails at VM creation if the label is already in use.

### VM Sizes

| Size | vCPU | RAM | Notes |
|---|---|---|---|
| `Standard_DS1_v2` | 1 | 3.5 GB | Default — reliable across most regions |
| `Standard_B2s` | 2 | 4 GB | Good balance of cost/performance |
| `Standard_B1s` | 1 | 1 GB | Cheapest — may be unavailable in some regions |

If you get `SkuNotAvailable`, try a different `vmSize` or `region`.

---

## Step 4 — Make Sure the Repo is Public

The Azure VM clones the portfolio repo directly from GitHub. The repo must be publicly accessible (no auth required for `git clone`).

---

## Step 5 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

The script will:

1. Log in to Azure with the service principal
2. Create resource group `portfolio-rg` in your region (idempotent)
3. Create VM `portfolio-portfolio` with the DNS label attached to its public IP
4. Open ports 80 and 443
5. Wait for SSH to become available
6. SSH in and run: install Node via nvm → clone repo → add 2 GB swap → `npm run build` → `npm start`
7. SSH in and install Caddy, write `/etc/caddy/Caddyfile` pointing to `localhost:3000`
8. Caddy obtains a Let's Encrypt cert for `<label>.<region>.cloudapp.azure.com` automatically
9. Write the HTTPS URL to `.env.local` so the portfolio links to cloud project URLs

**Re-running deploy never creates a duplicate VM** — VMs are found by name (`portfolio-<id>`) in the resource group.

---

## What URL to Use

After deploy, the console prints:

```
[deploy]  portfolio    https://sidd-portfolio.westus2.cloudapp.azure.com
```

Navigate to that URL in any browser. The certificate is trusted — no browser warning.

---

## How Project URLs Flow to the Portfolio

When any cloud project is deployed, its URL is written to `.env.local`:

```
FLOWERS_URL=http://1.2.3.4:3001
LABYRINTH_URL=https://54-183-164-223.sslip.io
FISHING_URL=http://9.10.11.12:8080
```

After deploying all projects, the script runs `sync_urls_to_portfolio_vm`:

1. Uploads `.env.local` to the portfolio VM at `$HOME/app/.env.local`
2. Restarts `npm start` on the portfolio VM (no rebuild needed — `process.env` is read at startup)

The portfolio's "Launch Demo" buttons automatically link to the live cloud URLs.

---

## Refreshing (Pull Latest Code + Restart)

```bash
./deploy.sh --cloud cloud.json --refresh portfolio
```

This SSHes into the VM, runs `git pull`, rebuilds (`npm run build`), and restarts `npm start`. Caddy is not reinstalled — the existing certificate remains valid.

Refreshing also re-syncs `.env.local` so the portfolio picks up any URL changes.

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
| Swap | 2 GB (added during Next.js deploy to prevent OOM during build) |

---

## Troubleshooting

**"No subscriptions found for this service principal"**
The SP was created without a role assignment. See Step 2 — assign Contributor on your subscription.

**`SkuNotAvailable` for a VM size**
Change `vmSize` in `cloud.json` or pick a different `region`. Availability varies by region and time.

**VM created but app never started (empty VM)**
The SSH daemon was not ready when the setup script ran. Re-run:
```bash
./deploy.sh --cloud cloud.json --refresh portfolio
```

**`nvm install` failed**
Happens if curl is not installed when nvm runs. The `nextjs_setup_script` installs curl first. If the issue persists, SSH into the VM and run `nvm install --lts` manually to see the error.

**Next.js build killed (SIGKILL)**
The build ran out of memory. The script adds a 2 GB swap file and sets `NODE_OPTIONS=--max-old-space-size=2048`. If the VM has less than 3.5 GB total memory+swap, try `Standard_B2s`.

**Caddy: "failed to obtain certificate"**
Port 80 must be publicly reachable for the HTTP-01 challenge. Check the NSG rules: `az network nsg list --resource-group portfolio-rg`. On the VM: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.

**Portfolio still shows `localhost` URLs**
`.env.local` is read at `npm start` time, not at build time. After any cloud project is deployed or refreshed, the script automatically calls `sync_urls_to_portfolio_vm`. If this step was skipped, run:
```bash
./deploy.sh --cloud cloud.json --refresh portfolio
```
