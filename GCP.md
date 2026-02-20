# Deploying to GCP (Google Cloud)

The deploy script can provision a GCP `e2-micro` instance running Ubuntu 22.04, deploy any project to it, and serve it over **HTTPS via [sslip.io](https://sslip.io) + Caddy** — no domain purchase required.

---

## Instance Details

| Property | Value |
|---|---|
| Machine type | `e2-micro` (Always Free in `us-east1`, `us-west1`, `us-central1`) |
| OS | Ubuntu 22.04 LTS |
| SSH key | `~/.ssh/portfolio_deploy` (4096-bit RSA, auto-generated) |
| SSH user | `ubuntu` |
| Instance name | `portfolio-<id>` |
| Zone | `<region>-a` |
| Firewall tag | `portfolio-server` |

> **Always Free tier:** One `e2-micro` VM per month at no cost in the three US regions listed above. Check https://cloud.google.com/free for current limits.

---

## How HTTPS Works Without a Domain

[sslip.io](https://sslip.io) is a free public DNS service that resolves hostnames like `34-56-78-90.sslip.io` to the IP `34.56.78.90`. This gives your GCP instance a stable domain name that Let's Encrypt can issue a trusted certificate for.

The deploy script:
1. Deploys your app on its internal port (e.g. 8080)
2. Installs [Caddy](https://caddyserver.com/) on the VM
3. Configures Caddy to listen on `<ip-with-dashes>.sslip.io` (ports 80/443)
4. Caddy automatically obtains a Let's Encrypt certificate for that hostname
5. Caddy reverse-proxies HTTPS traffic to your app

**Example:** GCP IP `34.56.78.90` → URL `https://34-56-78-90.sslip.io`

**Port 80 must remain open** — Let's Encrypt's HTTP-01 challenge requires it. The deploy script creates the `portfolio-caddy` firewall rule opening ports 80 and 443 automatically.

---

## Step 1 — Create a GCP Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click the project dropdown → **New Project**
3. Name it (e.g. `portfolio-deploy`) and create it
4. Note the **Project ID** (used in the service account key)

Enable the Compute Engine API:

```bash
gcloud services enable compute.googleapis.com --project <your-project-id>
```

Or enable it in the Console: **APIs & Services → Enable APIs and Services → search "Compute Engine API"**.

---

## Step 2 — Create a Service Account

1. Go to **IAM & Admin → Service Accounts → Create Service Account**
2. Name: `portfolio-deploy`
3. **Grant roles:**
   - `Compute Admin`
   - `Service Account User`
4. Click **Done**

---

## Step 3 — Download a Service Account Key

1. Click on the service account you just created
2. **Keys → Add Key → Create new key → JSON**
3. Download the file (e.g. `gcp-service-account.json`)

The file looks like:

```json
{
  "type": "service_account",
  "project_id": "portfolio-deploy",
  "private_key_id": "abc123...",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "client_email": "portfolio-deploy@portfolio-deploy.iam.gserviceaccount.com",
  ...
}
```

The deploy script reads `project_id` from this file automatically.

> **Security:** Keep this file outside the portfolio repo. Add its path to `.gitignore` if needed.

---

## Step 4 — Install the gcloud CLI

```bash
# macOS
brew install google-cloud-sdk

# Or download from:
# https://cloud.google.com/sdk/docs/install
```

Verify: `gcloud --version`

---

## Step 5 — Add an Entry to `cloud.json`

Copy `cloud.json.template` to `cloud.json` if you haven't already:

```bash
cp cloud.json.template cloud.json
```

Example entry for the Fishing game (Go/WASM, served by Python):

```json
{
  "fishing": {
    "repoUrl": "https://github.com/Siderskini/LearningGo/tree/main/fishing/web",
    "type": "wasm",
    "port": 8080,
    "provider": "gcp",
    "region": "us-central1",
    "authKey": "/home/you/gcp-service-account.json"
  }
}
```

Example entry for the Flowers Rails app:

```json
{
  "flowers": {
    "repoUrl": "https://github.com/Siderskini/RubyOnRails/tree/main/Flowers",
    "type": "rails",
    "port": 3001,
    "provider": "gcp",
    "region": "us-central1",
    "authKey": "/home/you/gcp-service-account.json"
  }
}
```

### Fields

| Field | Description |
|---|---|
| `repoUrl` | GitHub repo URL. Use `/tree/branch/subdir` for a subdirectory. |
| `type` | `rails`, `node`, `wasm`, or `nextjs` |
| `port` | Internal port the app listens on |
| `provider` | `gcp` |
| `region` | GCP region (e.g. `us-central1`, `us-east1`, `us-west1`, `europe-west1`) |
| `authKey` | Absolute or relative path to your service account JSON key |

---

## Step 6 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

The script will:

1. Activate the service account: `gcloud auth activate-service-account --key-file=...`
2. Set the GCP project from the key file
3. Create firewall rule `portfolio-app` allowing the app port, and `portfolio-caddy` allowing ports 80 and 443 — both tagged `portfolio-server` (idempotent)
4. Launch an `e2-micro` Ubuntu 22.04 instance in zone `<region>-a` tagged `portfolio-server`
5. Wait ~20 seconds for the VM to boot and SSH to become available
6. SSH in and run the project setup (installs Node/Ruby/Python, clones repo, starts app)
7. Install Caddy and configure it for `https://<ip-with-dashes>.sslip.io`
8. Write the HTTPS URL to `.env.local`

**Re-running deploy never creates a duplicate VM** — instances are found by name (`portfolio-<id>`) in the zone.

---

## What URL to Use

After deploy, the console prints:

```
[deploy]  fishing      https://34-56-78-90.sslip.io
```

This is also written to `.env.local`:

```
FISHING_URL=https://34-56-78-90.sslip.io
```

The portfolio reads this at startup and uses it for the "Launch Demo" button on the Fishing card. The certificate is trusted — no browser warning.

---

## How Project URLs Flow to the Portfolio

When cloud projects are deployed, their URLs are written to `.env.local`. If the portfolio is also cloud-deployed on Azure, the script automatically uploads `.env.local` to the portfolio VM and restarts `npm start` — no rebuild needed.

If the portfolio is running locally, restart it to pick up the new URLs:

```bash
./deploy.sh --refresh portfolio
```

---

## Refreshing (Pull Latest Code + Restart)

```bash
./deploy.sh --cloud cloud.json --refresh fishing
```

This SSHes in, runs `git pull`, and restarts the process. The VM is not reprovisioned.

---

## Troubleshooting

**"Permission denied" on gcloud commands**
The service account needs `Compute Admin` and `Service Account User` roles. Grant them in **IAM & Admin → IAM**.

**Firewall rule creation fails**
If `portfolio-app` or `portfolio-caddy` already exists with different settings, the script ignores the error (`|| true`). Verify the existing rules in **VPC Network → Firewall** — `portfolio-caddy` must allow TCP 80 and 443.

**SSH times out after instance creation**
The script waits 20 seconds after launch. GCP instances typically boot in 30–60 seconds. If SSH fails, wait a minute and run:
```bash
./deploy.sh --cloud cloud.json --refresh fishing
```

**App is reachable on its port but not via sslip.io**
Caddy reverse-proxies from the sslip.io hostname on 443 to `localhost:<port>`. If Caddy isn't running, SSH into the VM and check: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.

**Caddy fails to obtain a certificate**
Port 80 must be reachable from the internet for the HTTP-01 challenge. Verify the `portfolio-caddy` firewall rule:
```bash
gcloud compute firewall-rules describe portfolio-caddy
gcloud compute instances describe portfolio-fishing --zone=us-central1-a --format="value(tags.items)"
```

**`e2-micro` not available in chosen region**
Try `us-central1`, `us-east1`, or `us-west1` — these support `e2-micro` and are in the Always Free tier.
