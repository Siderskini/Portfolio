# Hosting Guide

This portfolio and its three live project demos can be run entirely on one local machine, or each demo can be deployed independently to AWS, Azure, or GCP — in any combination.

---

## Services and Ports

| Service | Default URL | Technology |
|---|---|---|
| Portfolio | http://localhost:3000 | Next.js (Node.js) |
| Flowers | http://localhost:3001 | Ruby on Rails |
| Labyrinth | https://localhost:4000 | Node.js + Socket.io (HTTPS) |
| Fishing Game | http://localhost:8080 | Python static server (Go/WASM) |

---

## Local Deploy (All on One Machine)

### Prerequisites

| Tool | Required for | Install |
|---|---|---|
| Node.js + npm | Portfolio, Labyrinth | https://nodejs.org |
| Ruby 3.3 | Flowers | System package or rbenv |
| `/usr/bin/bundle3.3` | Flowers | `gem install bundler` |
| Python 3 | Fishing | Included on most systems |
| OpenSSL | Labyrinth SSL certs | System package |
| git | Cloning repos | System package |

### Run

```bash
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Clone `RubyOnRails`, `Labyrinth`, and `LearningGo` into `projects/` (skipped if already present)
2. Install dependencies for each project
3. Generate self-signed SSL certs for Labyrinth and patch its hardcoded server IP to `localhost`
4. Start all four services in the background and write logs to `logs/`
5. Print a summary of running URLs
6. Keep running until `Ctrl+C`, which cleanly kills all background processes

### Logs

Each service writes to its own log file:

```
logs/flowers.log
logs/labyrinth.log
logs/fishing.log
logs/portfolio.log
```

PIDs are saved to `logs/<id>.pid` and hosts to `logs/<id>.host` for use by the refresh command.

---

## Cloud Deploy (Arbitrarily Distribute Projects Across Providers)

Any or all of the three demo projects can be deployed to a cloud VM instead of running locally. The portfolio itself always runs locally.

### Step 1 — Create `cloud.json`

Copy the template and fill in real values:

```bash
cp cloud.json.template cloud.json
```

`cloud.json` is gitignored and never committed. It contains paths to your auth credential files. Only include entries for the projects you want cloud-hosted; omit an entry to keep that project local.

#### Schema

```json
{
  "<project-id>": {
    "repoUrl":  "GitHub URL (may point to a subdirectory via /tree/branch/subdir)",
    "type":     "rails | node | wasm",
    "port":     <port number>,
    "provider": "aws | azure | gcp",
    "region":   "<provider region string>",
    "authKey":  "/absolute/path/to/credentials/file"
  }
}
```

#### Project IDs

| ID | Project |
|---|---|
| `flowers` | Flowers (Rails) |
| `labyrinth` | Labyrinth (Node.js) |
| `fishing` | Fishing Game (WASM) |

### Step 2 — Prepare Provider Credentials

#### AWS
`authKey` is the path to an AWS credentials file in the standard INI format:

```ini
[default]
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

The AWS CLI must be installed: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html

The deploy script will:
- Import `~/.ssh/portfolio_deploy.pub` as a key pair named `portfolio-deploy`
- Create a security group opening SSH (22) and the app port
- Launch a `t2.micro` Ubuntu 22.04 instance tagged `portfolio-<id>`

#### Azure
`authKey` is the path to a service principal JSON file created with:

```bash
az ad sp create-for-rbac --name "portfolio-deploy" --sdk-auth > azure-sp.json
```

The Azure CLI must be installed: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli

The deploy script will:
- Create a resource group named `portfolio-rg` in your specified region
- Launch a `Standard_B1s` Ubuntu 22.04 VM named `portfolio-<id>`
- Open the app port with `az vm open-port`

#### GCP
`authKey` is the path to a service account key JSON file downloaded from the GCP Console (IAM → Service Accounts → Keys). The service account needs `Compute Admin` and `Service Account User` roles.

The `gcloud` CLI must be installed: https://cloud.google.com/sdk/docs/install

The project ID is read automatically from the key file. The deploy script will:
- Create a firewall rule `portfolio-app` allowing the app port
- Launch an `e2-micro` Ubuntu 22.04 instance named `portfolio-<id>`

#### Oracle Cloud (OCI)
OCI requires two things that cannot be derived from a single credentials file: a **compartment OCID** and a **subnet OCID**. For this reason, `authKey` points to a small JSON file you create that bundles all OCI-specific config together:

```json
{
  "configFile":    "/home/you/.oci/config",
  "profile":       "DEFAULT",
  "compartmentId": "ocid1.compartment.oc1...<your-compartment-ocid>",
  "subnetId":      "ocid1.subnet.oc1...<your-subnet-ocid>"
}
```

Save this file anywhere (e.g. `~/oci-portfolio-auth.json`) and set `authKey` to its path.

**One-time manual prerequisite — open the app port in your subnet's security list:**
Unlike AWS/Azure/GCP, OCI does not support adding individual firewall rules via a single CLI call without replacing the full list. Open the app port once in the OCI Console before deploying:
1. Go to **Networking → Virtual Cloud Networks → your VCN → Security Lists**
2. Add an Ingress Rule: Source `0.0.0.0/0`, Protocol TCP, Destination Port = the port for this project

The `oci` CLI must be installed: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm

Configure it with `oci setup config` and verify with `oci iam user get --user-id <your-user-ocid>`.

The deploy script will:
- Resolve the latest Ubuntu 22.04 image in your region automatically
- Launch a `VM.Standard.E2.1.Micro` instance (Always Free eligible) named `portfolio-<id>`
- Inject `~/.ssh/portfolio_deploy.pub` as the authorized SSH key at launch

**`cloud.json` entry for OCI:**
```json
"fishing": {
  "repoUrl":  "https://github.com/Siderskini/LearningGo/tree/main/fishing/web",
  "type":     "wasm",
  "port":     8080,
  "provider": "oci",
  "region":   "us-ashburn-1",
  "authKey":  "/home/you/oci-portfolio-auth.json"
}
```

Common OCI regions: `us-ashburn-1`, `us-phoenix-1`, `uk-london-1`, `eu-frankfurt-1`, `ap-tokyo-1`.

### Step 3 — Run

```bash
./deploy.sh --cloud cloud.json
```

For each project in `cloud.json`, the script:
1. Provisions a VM on the specified provider (creates once, reuses on subsequent runs — VMs are identified by name tag)
2. Generates `~/.ssh/portfolio_deploy` (RSA 4096) if it doesn't exist and imports it to the provider
3. SSHes in and runs the appropriate setup script:
   - **rails**: installs rbenv + Ruby 3.2.3 + Bundler, clones repo, runs migrations and seeds, starts Rails in production mode
   - **node**: installs nvm + Node LTS, clones repo, generates SSL certs, patches hardcoded IP to the VM's public IP, starts with `node index.js`
   - **wasm**: installs Python 3, clones repo, starts `python3 -m http.server`
4. Writes the live URL to `.env.local` (e.g. `FLOWERS_URL=http://1.2.3.4:3001`)
5. Starts the portfolio locally — it reads `.env.local` at startup and links to the cloud URLs instead of localhost

Projects not listed in `cloud.json` are deployed locally as usual.

---

## Refreshing Individual Projects

Pull the latest code and restart a single project without touching anything else:

```bash
# Local project
./deploy.sh --refresh flowers

# Cloud project
./deploy.sh --cloud cloud.json --refresh labyrinth
```

For **local** projects: kills the running process by PID and restarts it.
For **cloud** projects: SSHes into the existing VM, runs `git pull`, and restarts the process in place. The VM is not reprovisioned.

---

## How URLs Flow from Cloud to Portfolio

When a project is cloud-deployed, its URL is written to `.env.local`:

```
FLOWERS_URL=http://1.2.3.4:3001
LABYRINTH_URL=https://5.6.7.8:4000
FISHING_URL=http://9.10.11.12:8080
```

`src/lib/projects.ts` reads these at server startup with `process.env.FLOWERS_URL ?? "http://localhost:3001"` etc. The portfolio's "Launch Demo" buttons automatically link to the cloud instance. Restart the portfolio after any URL change to pick up the new `.env.local`.

---

## VM Naming Reference

VMs are named `portfolio-<id>` and looked up by that name on each deploy run, so re-running the script never creates duplicate VMs.

| Project | AWS tag | Azure VM name | GCP instance name | OCI display name |
|---|---|---|---|---|
| Flowers | `portfolio-flowers` | `portfolio-flowers` | `portfolio-flowers` | `portfolio-flowers` |
| Labyrinth | `portfolio-labyrinth` | `portfolio-labyrinth` | `portfolio-labyrinth` | `portfolio-labyrinth` |
| Fishing | `portfolio-fishing` | `portfolio-fishing` | `portfolio-fishing` | `portfolio-fishing` |

---

## File Reference

| File | Purpose |
|---|---|
| `deploy.sh` | Main deploy/refresh script |
| `cloud.json.template` | Template for cloud config — copy to `cloud.json` and fill in |
| `cloud.json` | Your cloud config — **gitignored, never commit** |
| `logs/<id>.log` | stdout/stderr of each running service |
| `logs/<id>.pid` | PID of each local process (used by `--refresh`) |
| `logs/<id>.host` | Recorded URL of each service (used by `--refresh` for cloud) |
| `.env.local` | Cloud URLs written here by deploy script — read by Next.js at startup |
| `projects/` | Cloned project repos — gitignored |

---

## Troubleshooting

**Bundler permission error on Flowers**
The script uses `/usr/bin/bundle3.3` and installs gems into `vendor/bundle` to avoid needing root. If you see a different bundler path, confirm the binary exists: `ls /usr/bin/bundle*`

**"Required file not found" when running bundle**
The shebang in `/usr/local/bin/bundle` points to `ruby3.2`, which may not exist. The deploy script strips `/usr/local/bin` from PATH to avoid this and uses `/usr/bin/bundle3.3` directly.

**Labyrinth "refused to connect" or cert warning in browser**
Labyrinth runs on HTTPS with a self-signed certificate. Before clicking "Launch Demo" in the portfolio, navigate directly to `https://localhost:4000` and accept the browser's security warning once.

**Portfolio still shows localhost URLs after a cloud deploy**
The portfolio reads `.env.local` at process startup. After `deploy.sh --cloud cloud.json` writes new URLs, restart the portfolio: `./deploy.sh --refresh portfolio`

**Cloud VM exists but app is not running**
The VM was provisioned but the app process may have died. Re-run the app setup without reprovisioning: `./deploy.sh --cloud cloud.json --refresh <id>`

**SSH connection refused on first cloud deploy**
The VM may need more time to boot. The script waits 15–20 seconds after instance creation, but slow regions may need longer. Re-run `--refresh <id>` once the VM is fully up.

**OCI: app is unreachable after deploy**
The `VM.Standard.E2.1.Micro` instance was created but the port is blocked. OCI does not allow the deploy script to add individual ingress rules without replacing the entire security list. Open the port manually in the OCI Console under **Networking → Virtual Cloud Networks → your VCN → Security Lists** (see the OCI section above).

**OCI: `compartmentId` or `subnetId` not found**
The OCI `authKey` JSON must include both `compartmentId` and `subnetId`. Find your compartment OCID in the OCI Console under **Identity → Compartments** and your subnet OCID under **Networking → Virtual Cloud Networks → your VCN → Subnets**.
