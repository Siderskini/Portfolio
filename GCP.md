# Deploying to GCP (Google Cloud)

The deploy script provisions a GCP `e2-micro` instance running Ubuntu 22.04, deploys your project, and serves it over **HTTPS via [sslip.io](https://sslip.io) + Caddy** — no domain purchase required.

For wasm projects, you can instead deploy to GCS object storage — no VM needed. See the [Wasm Object Storage](#wasm-object-storage-gcs) section below.

---

## How HTTPS Works Without a Domain

[sslip.io](https://sslip.io) is a free public DNS service that resolves `34-56-78-90.sslip.io` to the IP `34.56.78.90`. This gives your GCP instance a stable domain name that Let's Encrypt can issue a trusted certificate for.

The deploy script:
1. Deploys your app on its internal port
2. Installs [Caddy](https://caddyserver.com/) on the VM
3. Configures Caddy to listen on `<ip-with-dashes>.sslip.io` (ports 80/443)
4. Caddy automatically obtains a Let's Encrypt certificate
5. Caddy reverse-proxies HTTPS traffic to your app

**Example:** GCP IP `34.56.78.90` → URL `https://34-56-78-90.sslip.io`

---

## Instance Details

| Property | Value |
|---|---|
| Machine type | `e2-micro` (Always Free in `us-central1`, `us-west1`, `us-east1`) |
| OS | Ubuntu 22.04 LTS |
| SSH key | `~/.ssh/portfolio_deploy` (4096-bit RSA, auto-generated) |
| SSH user | `ubuntu` |
| Instance name | `portfolio-<id>` |
| Zone | `<region>-a` |
| Firewall tag | `portfolio-server` |

> **Always Free tier:** One `e2-micro` VM per month at no cost in the three US regions listed. See https://cloud.google.com/free for current limits.

> **GCP region format:** GCP regions use the format `us-central1` (no hyphen before the number), not `us-central-1` as in AWS. Using an AWS-style region name will cause an error.

> **Zone availability:** The script appends `-a` to your region to form the zone (e.g. `us-central1` → zone `us-central1-a`). Note that `us-east1` does **not** have a zone `a` — use `us-central1` or `us-west1` instead if you want Always Free.

---

## Step 1 — Create a GCP Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click the project dropdown → **New Project**
3. Name it and create it; note the **Project ID**

Enable the Compute Engine API:

```bash
gcloud services enable compute.googleapis.com --project <your-project-id>
```

Or in the Console: **APIs & Services → Enable APIs and Services → search "Compute Engine API"**.

---

## Step 2 — Create a Service Account

1. Go to **IAM & Admin → Service Accounts → Create Service Account**
2. Name: `portfolio-deploy`
3. **Grant roles:** `Compute Admin` and `Service Account User`
4. Click **Done**

---

## Step 3 — Download a Service Account Key

1. Click on the service account you just created
2. **Keys → Add Key → Create new key → JSON**
3. Download the file (e.g. `gcp-service-account.json`)

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

```bash
cp cloud.json.template cloud.json
```

Example entry for Flowers (Ruby on Rails):

```json
{
  "flowers": {
    "repoUrl": "https://github.com/Siderskini/RubyOnRails/tree/main/Flowers",
    "type": "rails",
    "port": 3001,
    "provider": "gcp",
    "region": "us-central1",
    "authKey": "./gcp-service-account.json"
  }
}
```

Example entry for Labyrinth (Node.js):

```json
{
  "labyrinth": {
    "repoUrl": "https://github.com/Siderskini/Labyrinth",
    "type": "node",
    "port": 4000,
    "provider": "gcp",
    "region": "us-central1",
    "authKey": "./gcp-service-account.json"
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
| `region` | GCP region — use format `us-central1`, **not** `us-central-1` |
| `authKey` | Relative or absolute path to your service account JSON key |

---

## Step 6 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

The script will:

1. Activate the service account and set the GCP project from the key file
2. Create firewall rules `portfolio-app` (app port) and `portfolio-caddy` (80/443) tagged `portfolio-server` — idempotent
3. Launch an `e2-micro` Ubuntu 22.04 instance in zone `<region>-a` (or reuse/start an existing one)
4. Wait for SSH readiness
5. Run an Ansible playbook: install the runtime (Node/Ruby), clone the repo, start the app as a systemd service
6. Install Caddy and configure it for `https://<ip-with-dashes>.sslip.io`
7. Write the HTTPS URL to `.env.local`

Re-running deploy never creates a duplicate VM — instances are found by name in the zone.

---

## Wasm Object Storage (GCS)

For `type: "wasm"` projects, adding a `bucket` field deploys to Google Cloud Storage instead of a VM:

```json
{
  "fishing": {
    "repoUrl": "https://github.com/Siderskini/LearningGo/tree/main/fishing/web",
    "type": "wasm",
    "provider": "gcp",
    "region": "us-central1",
    "authKey": "./gcp-service-account.json",
    "bucket": "my-portfolio-fishing"
  }
}
```

Bucket names must be globally unique. The service account needs `Storage Admin` role for this path.

---

## What URL to Use

After deploy, the console prints:

```
[deploy]  flowers    https://34-56-78-90.sslip.io
```

This is also written to `.env.local`:

```
FLOWERS_URL=https://34-56-78-90.sslip.io
```

---

## Refreshing (Pull Latest Code + Restart)

```bash
./deploy.sh --cloud cloud.json --refresh flowers
```

For VM projects: SSHes in, runs `git pull`, and restarts the service via Ansible. The VM is not reprovisioned.

For wasm+GCS: re-clones/pulls locally and re-uploads all files to the bucket.

---

## Troubleshooting

**"Permission denied" on gcloud commands**
The service account needs `Compute Admin` and `Service Account User` roles. Grant them in **IAM & Admin → IAM**.

**"Permission denied on 'locations/...' (or it may not exist)"**
You used an AWS-style region name (e.g. `us-east-1` instead of `us-east1`). GCP regions do not have a hyphen before the number. Fix the `region` field in `cloud.json`.

**Zone `us-east1-a` does not exist**
`us-east1` only has zones `b`, `c`, and `d` — it has no zone `a`. Use `us-central1` or `us-west1` instead (both have zone `a` and are Always Free eligible).

**SSH times out after instance creation**
The script waits for the instance to reach RUNNING state, but SSH can take another 30–60 seconds after that. Run:
```bash
./deploy.sh --cloud cloud.json --refresh <id>
```

**Caddy fails to obtain a certificate**
Port 80 must be reachable from the internet. Verify the `portfolio-caddy` firewall rule:
```bash
gcloud compute firewall-rules describe portfolio-caddy
```
On the VM: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.

**`e2-micro` not available in chosen region**
Use `us-central1`, `us-east1`, or `us-west1`. These are the Always Free tier regions and reliably support `e2-micro`.
