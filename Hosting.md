# Hosting Guide

This portfolio and its three live project demos can run entirely on one local machine, or each demo can be deployed independently to AWS, Azure, GCP, or OCI — in any combination.

---

## Services and Ports

| Service | Default Local URL | Technology |
|---|---|---|
| Portfolio | http://localhost:3000 | Next.js |
| Flowers | http://localhost:3001 | Ruby on Rails |
| Labyrinth | https://localhost:4000 | Node.js + Socket.io (HTTPS) |
| Fishing Game | http://localhost:8080 | Go/WASM (Python static server) |

---

## Local Deploy

### Prerequisites

| Tool | Required for | Notes |
|---|---|---|
| `git` | All projects | System package |
| `python3` | Fishing Game | Included on most systems |
| `curl` | Node/Ruby install | System package |
| Build tools (`make`, `gcc`) | Flowers (Ruby compile) | `xcode-select --install` on macOS; `apt install build-essential` on Debian |
| Ruby dev headers | Flowers (Ruby compile) | Debian/Ubuntu only: `sudo apt install libssl-dev zlib1g-dev libreadline-dev libyaml-dev libffi-dev` |
| Homebrew | macOS Ruby build | Needed to link openssl/zlib/readline for Ruby compilation |

No global Ruby or Node installation is required. The deploy script sets up project-local runtimes automatically:
- **Ruby** — installed into `.rbenv/` inside the portfolio repo (first run compiles Ruby from source; subsequent runs reuse it)
- **Node.js** — installed into `.nvm/` inside the portfolio repo

### Run

```bash
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Set up project-local Ruby (rbenv) and Node.js (nvm) environments on first run
2. Clone `RubyOnRails`, `Labyrinth`, and `LearningGo` into `projects/` (skipped if already present)
3. Install dependencies for each project
4. Start all four services in the background
5. Print a summary of running URLs
6. Keep running until `Ctrl+C`, which cleanly stops all background processes

### Logs

Local service logs are written to:

```
logs/flowers.log
logs/labyrinth.log
logs/fishing.log
logs/portfolio.log
```

PIDs are saved to `logs/<id>.pid` and hosts to `logs/<id>.host`.

---

## Cloud Deploy

Any or all projects can be deployed to cloud VMs. Projects not in `cloud.json` run locally as usual.

### Prerequisites (Cloud Only)

Ansible is required for all cloud VM deployments:

```bash
# macOS
brew install ansible

# Linux
pip install ansible
```

Install the required Ansible collection:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

Also install the CLI for whichever cloud provider(s) you are using. See the provider-specific guides:
- [AWS.md](AWS.md)
- [Azure.md](Azure.md)
- [GCP.md](GCP.md)
- [OCI.md](OCI.md)

### Step 1 — Create `cloud.json`

```bash
cp cloud.json.template cloud.json
```

`cloud.json` is gitignored and never committed. Include only the projects you want cloud-hosted; omit an entry to keep that project local.

#### Project IDs

The key in `cloud.json` **must exactly match** the project ID used by the deploy script. The valid IDs are:

| ID | Project |
|---|---|
| `flowers` | Flowers (Ruby on Rails) |
| `labyrinth` | Labyrinth (Node.js) |
| `fishing` | Fishing Game (Go/WASM) |
| `portfolio` | Portfolio (Next.js) |

#### Schema

```json
{
  "<project-id>": {
    "repoUrl":        "GitHub URL (may include /tree/branch/subdir for a subdirectory)",
    "type":           "rails | node | wasm | nextjs",
    "port":           3001,
    "provider":       "aws | azure | gcp | oci",
    "region":         "<provider region string>",
    "authKey":        "./path/to/credentials.json",

    "bucket":         "bucket-name (wasm only — triggers object storage instead of VM)",
    "storageAccount": "globally-unique-name (Azure wasm only, ≤24 chars, lowercase)",
    "dnsLabel":       "my-label (Azure only — gives HTTPS via <label>.<region>.cloudapp.azure.com)",
    "vmSize":         "Standard_DS1_v2 (Azure only — defaults to Standard_DS1_v2)"
  }
}
```

The `port` field is ignored for wasm projects deployed to object storage.

#### Wasm Object Storage (No VM Required)

For `type: "wasm"` projects, adding a `bucket` field deploys the files to cloud object storage instead of a VM — no server to maintain, no SSH needed:

```json
"fishing": {
  "repoUrl":  "https://github.com/Siderskini/LearningGo/tree/main/fishing/web",
  "type":     "wasm",
  "provider": "oci",
  "region":   "us-ashburn-1",
  "authKey":  "./oci-credentials.json",
  "bucket":   "bucket-portfolio"
}
```

The deploy script clones the repo locally, uploads all files to the bucket with correct Content-Types, and writes the public URL to `.env.local`. Bucket is created automatically if it doesn't exist.

To force VM hosting for a wasm project that has a `bucket` configured:
```bash
./deploy.sh --cloud cloud.json --vm
```

### Step 2 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

For each VM-hosted project, the script:
1. Provisions a VM (creates once, reuses/restarts on subsequent runs — VMs are identified by name)
2. Generates `~/.ssh/portfolio_deploy` (RSA 4096) if it doesn't exist and syncs it to the provider
3. Waits for SSH to become available
4. Runs an Ansible playbook that installs the runtime (Ruby/Node), clones the repo, and starts the app as a systemd service
5. Installs Caddy and obtains a trusted HTTPS certificate (sslip.io on AWS/GCP/OCI; Azure DNS label on Azure)
6. Writes the live URL to `.env.local`

For wasm object storage projects, steps 1–5 are skipped entirely.

### Cloud Logs

Cloud VM services log to the system journal. To follow logs on a running VM:

```bash
ssh -i ~/.ssh/portfolio_deploy ubuntu@<ip>   # (use 'opc' for OCI)

# Follow live logs
journalctl -u flowers -f
journalctl -u portfolio -f

# Recent history
journalctl -u flowers --since "1 hour ago"

# Check disk usage
journalctl --disk-usage
```

> Logs are bounded by systemd-journald's automatic rotation — they will never fill the disk.

---

## Refreshing Individual Projects

Pull the latest code and restart a single project without touching anything else:

```bash
# Local project
./deploy.sh --refresh flowers

# Cloud VM project
./deploy.sh --cloud cloud.json --refresh labyrinth

# Cloud wasm (re-uploads to object storage)
./deploy.sh --cloud cloud.json --refresh fishing
```

For cloud VM projects: runs `git pull` and restarts the service. The VM is not reprovisioned and Caddy is not reinstalled.

---

## How URLs Flow from Cloud to Portfolio

When a project is cloud-deployed, its URL is written to `.env.local`:

```
FLOWERS_URL=https://1-2-3-4.sslip.io
LABYRINTH_URL=https://5-6-7-8.sslip.io
FISHING_URL=https://objectstorage.us-ashburn-1.oraclecloud.com/n/.../o/index.html
```

`src/lib/projects.ts` reads these at server startup with `process.env.FLOWERS_URL ?? "http://localhost:3001"` etc. The "Launch Demo" buttons automatically link to cloud instances.

If the portfolio is cloud-deployed on Azure, the deploy script automatically syncs `.env.local` to the portfolio VM and restarts it — no manual action needed.

---

## VM Naming Reference

VMs are named `portfolio-<id>` and reused by name on every deploy run.

| Project | AWS / GCP / OCI name | Azure VM name |
|---|---|---|
| Portfolio | — | `portfolio-portfolio` |
| Flowers | `portfolio-flowers` | `portfolio-flowers` |
| Labyrinth | `portfolio-labyrinth` | `portfolio-labyrinth` |
| Fishing | `portfolio-fishing` | `portfolio-fishing` |

---

## File Reference

| File | Purpose |
|---|---|
| `deploy.sh` | Main deploy/refresh script |
| `cloud.json.template` | Template for cloud config — copy to `cloud.json` and fill in |
| `cloud.json` | Your cloud config — **gitignored, never commit** |
| `ansible/` | Ansible playbooks and roles used for VM setup |
| `logs/<id>.log` | stdout/stderr of each local service |
| `logs/<id>.pid` | PID of each local process (used by `--refresh`) |
| `logs/<id>.host` | Recorded URL of each service (used by `--refresh` for cloud) |
| `.env.local` | Cloud URLs written here by deploy script — read by Next.js at startup |
| `projects/` | Cloned project repos (local deploy only) — gitignored |
| `.rbenv/` | Project-local Ruby environment — gitignored |
| `.nvm/` | Project-local Node.js environment — gitignored |

---

## Troubleshooting

**First local deploy is slow**
The first run compiles Ruby from source via rbenv (5–10 minutes). Subsequent runs reuse the compiled binary and are fast.

**Ruby build fails on macOS (`cannot load such file -- zlib`)**
Homebrew must be installed so the build can link against its openssl/zlib/readline. Run `brew install openssl zlib readline` and retry.

**Labyrinth "refused to connect" or cert warning in browser**
Labyrinth runs on HTTPS with a self-signed certificate. Before clicking "Launch Demo" in the portfolio, navigate directly to `https://localhost:4000` and accept the browser's security warning once.

**Portfolio still shows localhost URLs after a cloud deploy**
The portfolio reads `.env.local` at process startup. After `deploy.sh --cloud cloud.json` writes new URLs, restart the portfolio: `./deploy.sh --refresh portfolio`

**`ansible-playbook: command not found`**
Install Ansible: `brew install ansible` (macOS) or `pip install ansible` (Linux), then install the collection: `ansible-galaxy collection install -r ansible/requirements.yml`.

**Cloud VM exists but app is not running**
The VM was provisioned but the Ansible run may have failed partway through. Re-run: `./deploy.sh --cloud cloud.json --refresh <id>`

**SSH times out on first cloud deploy**
The VM may still be booting. The script waits for SSH readiness, but slow regions can take longer. Re-run `--refresh <id>` once the VM is up.

**SSH "Permission denied (publickey)"**
The SSH key registered with the provider doesn't match your local `~/.ssh/portfolio_deploy`. For AWS, the script now deletes and re-imports the key pair on every deploy. For Azure, it runs `az vm user update` on existing VMs. To fix an existing VM manually:
- **AWS:** `aws ec2 delete-key-pair --key-name portfolio-deploy --region <region>` then redeploy
- **Azure:** `az vm user update --resource-group portfolio-rg --name portfolio-<id> --username ubuntu --ssh-key-value "$(cat ~/.ssh/portfolio_deploy.pub)"`

**OCI: app is unreachable after deploy**
OCI security list rules must be opened manually before deploying. See [OCI.md](OCI.md) Step 5.

**OCI: `compartmentId` or `subnetId` not found**
These fields are required in your `oci-credentials.json`. For wasm object storage deployments, `subnetId` is not needed. See [OCI.md](OCI.md).
