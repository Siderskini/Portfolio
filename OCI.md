# Deploying to OCI (Oracle Cloud Infrastructure)

The deploy script can provision an OCI `VM.Standard.E2.1.Micro` instance running Ubuntu 22.04, deploy any project to it, and serve it over **HTTPS via [sslip.io](https://sslip.io) + Caddy** — no domain purchase required.

---

## Instance Details

| Property | Value |
|---|---|
| Shape | `VM.Standard.E2.1.Micro` (Always Free eligible) |
| OS | Ubuntu 22.04 LTS |
| SSH key | `~/.ssh/portfolio_deploy` (4096-bit RSA, auto-generated) |
| SSH user | `ubuntu` |
| Display name | `portfolio-<id>` |

> **Always Free tier:** Oracle Cloud offers 2 `VM.Standard.E2.1.Micro` instances permanently for free. See https://www.oracle.com/cloud/free/ for current limits.

---

## How HTTPS Works Without a Domain

[sslip.io](https://sslip.io) is a free public DNS service that resolves hostnames like `132-145-100-50.sslip.io` to the IP `132.145.100.50`. This gives your OCI instance a stable domain name that Let's Encrypt can issue a trusted certificate for.

The deploy script:
1. Deploys your app on its internal port (e.g. 8080)
2. Installs [Caddy](https://caddyserver.com/) on the VM
3. Configures Caddy to listen on `<ip-with-dashes>.sslip.io` (ports 80/443)
4. Caddy automatically obtains a Let's Encrypt certificate for that hostname
5. Caddy reverse-proxies HTTPS traffic to your app

**Example:** OCI IP `132.145.100.50` → URL `https://132-145-100-50.sslip.io`

> **OCI firewall is manual:** Unlike AWS, Azure, and GCP, OCI's security list rules cannot be added via the CLI without replacing the entire list. You must open ports 80, 443, and the app port manually in the OCI Console before deploying (see Step 5).

---

## OCI Auth: Why It's Different

OCI's CLI uses `~/.oci/config` (an INI-format file) rather than a single JSON credentials file. Additionally, the deploy script needs two values that cannot be derived from the config file alone: a **compartment OCID** and a **subnet OCID**.

For this reason, `authKey` in `cloud.json` points to a small JSON file you create that bundles all required context:

```json
{
  "configFile":    "/home/you/.oci/config",
  "profile":       "DEFAULT",
  "compartmentId": "ocid1.compartment.oc1..<your-compartment-ocid>",
  "subnetId":      "ocid1.subnet.oc1..<your-subnet-ocid>"
}
```

The deploy script reads `configFile` and `profile` to locate your OCI credentials, and `compartmentId`/`subnetId` for instance provisioning.

---

## Step 1 — Create an OCI Account

Sign up at https://www.oracle.com/cloud/free/ — the Always Free tier is permanent and does not require a paid upgrade.

---

## Step 2 — Install and Configure the OCI CLI

```bash
# macOS / Linux
bash -c "$(curl -fsSL https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)"

# Or via pip
pip install oci-cli
```

Verify: `oci --version`

Run the interactive setup:

```bash
oci setup config
```

This creates `~/.oci/config` and generates an API signing key pair at `~/.oci/oci_api_key.pem`.

During setup you'll need:
- **User OCID:** OCI Console → top-right profile menu → User Settings → OCID
- **Tenancy OCID:** OCI Console → top-right profile menu → Tenancy → OCID
- **Region:** your home region (e.g. `us-ashburn-1`)

After setup, upload the generated public key to OCI:

1. Go to **Identity & Security → Users → your user → API Keys → Add API Key**
2. Choose **Paste Public Key**
3. Paste the contents of `~/.oci/oci_api_key_public.pem`

Verify the config works:

```bash
oci iam user get --user-id <your-user-ocid>
```

---

## Step 3 — Find Your Compartment OCID

OCI organizes resources into compartments. The root compartment has the same OCID as your tenancy.

1. Go to **Identity & Security → Compartments**
2. Click on your target compartment (or the root compartment)
3. Copy the **OCID**

---

## Step 4 — Set Up a VCN and Find Your Subnet OCID

The instance must be launched into a VCN subnet. OCI does not always create a default VCN — if none exists, create one first.

### If you have no VCN (create one)

1. Go to **Networking → Virtual Cloud Networks**
2. Click **Start VCN Wizard**
3. Select **Create VCN with Internet Connectivity** → click **Start VCN Wizard**
4. Fill in:
   - **VCN name:** e.g. `portfolio-vcn`
   - **Compartment:** your target compartment
   - Leave CIDR blocks at defaults (`10.0.0.0/16`, public subnet `10.0.0.0/24`)
5. Click **Next** → **Create**

This creates the VCN, an internet gateway, and a public subnet automatically.

### If the VCN exists but has no public subnet (create one)

A public subnet requires:
- Public IP assignment allowed on the subnet (`prohibit-public-ip-on-vnic = false`)
- A route table with a default route (`0.0.0.0/0`) to an Internet Gateway
- Ingress rules (security list and/or NSG) for SSH/app/Caddy ports

**1. Create an internet gateway** (skip if one already exists under the VCN):

1. Go to **Networking → Virtual Cloud Networks** → click your VCN
2. In the left sidebar, click **Internet Gateways → Create Internet Gateway**
3. Give it a name (e.g. `portfolio-igw`) and click **Create**

**2. Create a new route table for the public subnet:**

You can either edit an existing route table or create a dedicated one for the public subnet.

Important: edit the **subnet route table** under **VCN → Route Tables**.  
Do **not** edit the Internet Gateway's optional ingress route table. That ingress table only allows **private IP** targets and is not where you set `0.0.0.0/0 -> Internet Gateway`.

1. In the VCN, click **Route Tables → Create Route Table**
2. Give it a name (e.g. `public-route-table`)
3. Under **Route Rules**, click **+ Another Route Rule** and set:
   - **Target Type:** Internet Gateway
   - **Destination CIDR:** `0.0.0.0/0`
   - **Target:** the internet gateway you just created
4. Click **Create**

**3. Create the public subnet:**

1. In the VCN, click **Subnets → Create Subnet**
2. Fill in:
   - **Name:** e.g. `public-subnet`
   - **Subnet Type:** Regional
   - **CIDR Block:** `10.0.0.0/24`
   - **Route Table:** `public-route-table` (the one you just created)
   - **Subnet Access:** Public Subnet
   - **Security List:** Default Security List
3. Click **Create Subnet**

### Find the subnet OCID

1. Go to **Networking → Virtual Cloud Networks**
2. Click on your VCN
3. Click **Subnets** → click the **public** subnet (e.g. `Public Subnet-portfolio-vcn`)
4. Copy the **OCID**

> Use the **public** subnet — it has internet access via the internet gateway, which is required for the VM to be reachable and for Caddy to obtain a certificate.
>
> The deploy script now validates this and fails fast if the subnet is private or if no public IP is assigned.

---

## Step 5 — Open Ports in Security Rules (Manual Step Required)

**This must be done before deploying.** The deploy script does not modify your OCI firewall rules. You can configure these ports on the subnet security list, on an NSG, or both.

You need to open **four inbound ports** from `0.0.0.0/0`:
- `22` for SSH
- `80` for Let's Encrypt HTTP challenge
- `443` for HTTPS via Caddy
- your app port (e.g. `8080`)

1. Go to **Networking → Virtual Cloud Networks → your VCN → Security Lists**
2. Click on your security list (e.g. `Default Security List for...`)
3. **Add Ingress Rules** → add the following rules (one at a time):

   | Source CIDR | Protocol | Destination Port | Purpose |
   |---|---|---|---|
   | `0.0.0.0/0` | TCP | `22` | SSH deploy access |
   | `0.0.0.0/0` | TCP | `80` | Caddy HTTP (Let's Encrypt challenge) |
   | `0.0.0.0/0` | TCP | `443` | Caddy HTTPS |
   | `0.0.0.0/0` | TCP | `8080` (or your app port) | App internal port |

4. Click **Add Ingress Rules**

Repeat the app port row for each additional project on a different port.

Also ensure outbound access is allowed (default security lists usually allow all egress). The VM needs outbound internet for package install, git clone, and certificate issuance.

---

## Step 6 — Create `oci-credentials.json`

Save a file like `~/oci-credentials.json`:

```json
{
  "configFile":    "/home/you/.oci/config",
  "profile":       "DEFAULT",
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subnetId":      "ocid1.subnet.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

> **Security:** Keep this file outside the portfolio repo. It is already listed in `.gitignore`.
>
> `compartmentId` should be the compartment where the instance is created. For most setups, this should match the subnet's compartment.

---

## Step 7 — Add an Entry to `cloud.json`

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
    "provider": "oci",
    "region": "us-ashburn-1",
    "authKey": "/home/you/oci-credentials.json"
  }
}
```

### Fields

| Field | Description |
|---|---|
| `repoUrl` | GitHub repo URL. Use `/tree/branch/subdir` for a subdirectory. |
| `type` | `rails`, `node`, `wasm`, or `nextjs` |
| `port` | Internal port the app listens on (must be opened in security rules, along with 22, 80, and 443) |
| `provider` | `oci` |
| `region` | OCI region identifier (see below) |
| `authKey` | Absolute or relative path to your `oci-credentials.json` |

### OCI Regions

| Region | Identifier |
|---|---|
| US East (Ashburn) | `us-ashburn-1` |
| US West (Phoenix) | `us-phoenix-1` |
| UK South (London) | `uk-london-1` |
| Germany Central (Frankfurt) | `eu-frankfurt-1` |
| Japan East (Tokyo) | `ap-tokyo-1` |
| Australia East (Sydney) | `ap-sydney-1` |

Your Always Free instances must be in your **home region**.

---

## Step 8 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

The script will:

1. Read the OCI config file and profile from your `oci-credentials.json`
2. Validate subnet/network prerequisites (public subnet setting, default route target, and common firewall ports)
3. Find the latest Ubuntu 22.04 image in your region
4. Find the first availability domain in the region
5. Launch a `VM.Standard.E2.1.Micro` instance named `portfolio-<id>` (or reuse/start an existing stopped one)
6. Wait for SSH readiness
7. SSH in and run the project setup (installs Python/Node/Ruby, clones repo, starts app)
8. Install Caddy and configure it for `https://<ip-with-dashes>.sslip.io`
9. Write the HTTPS URL to `.env.local`

**Re-running deploy never creates a duplicate instance** — instances are looked up by display name and reused if they are not terminated.

---

## What URL to Use

After deploy, the console prints:

```
[deploy]  fishing      https://132-145-100-50.sslip.io
```

This is also written to `.env.local`:

```
FISHING_URL=https://132-145-100-50.sslip.io
```

The portfolio reads this at startup and uses it for the "Launch Demo" button on the Fishing card. The certificate is trusted — no browser warning.

---

## How Project URLs Flow to the Portfolio

When cloud projects are deployed, their URLs are written to `.env.local`. If the portfolio is cloud-deployed on Azure, the script automatically uploads `.env.local` to the portfolio VM and restarts `npm start` — no rebuild needed.

If the portfolio is running locally, restart it to pick up the new URLs:

```bash
./deploy.sh --refresh portfolio
```

---

## Refreshing (Pull Latest Code + Restart)

```bash
./deploy.sh --cloud cloud.json --refresh fishing
```

This SSHes in, runs `git pull`, and restarts the process. The instance is not reprovisioned.

---

## Troubleshooting

**"App is unreachable after deploy" / Caddy certificate error**
The most common cause on OCI. One or more ports are blocked by security rules (see Step 5). Make sure ports **22**, **80**, **443**, and the **app port** are all open from `0.0.0.0/0`.

If ports are open but Caddy still fails, SSH into the VM and check: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.

**"OCI instance ... has no public IP"**
Your subnet is likely private (`prohibit-public-ip-on-vnic=true`) or not configured for direct internet access. Use a public subnet and verify the route table has `0.0.0.0/0` to an Internet Gateway.

**Route table warning during deploy**
The script warns if the subnet route table has no default route to an Internet Gateway. In the OCI Console, open:
**Networking → VCNs → your VCN → Route Tables** and confirm the subnet's route table includes:
`Destination: 0.0.0.0/0`, `Target Type: Internet Gateway`.

If OCI shows `Rules in the route table must use private IP as a target`, you're editing the wrong table (Internet Gateway ingress route table). Go back to the **subnet route table** instead.

**Security list warning during deploy**
The script checks subnet security lists for common inbound ports and warns when rules appear missing. If you intentionally use NSGs, ensure NSG rules allow the same ports.

**"`compartmentId` or `subnetId` not found" error**
Your `oci-credentials.json` is missing one of these fields. Check spelling — they are case-sensitive.

**"Authorization failed or requested resource not found"**
The API key was not uploaded to OCI, or one of these values is wrong/mismatched: `compartmentId`, `subnetId`, `region`, or profile in `configFile`.

Common OCI pitfall: `compartmentId` does not match the subnet's compartment and your user has rights in only one of them.

Verify with:
```bash
oci iam user get --user-id <your-user-ocid>
oci network subnet get --subnet-id <your-subnet-ocid> --query 'data."compartment-id"' --raw-output
```

If needed, update `oci-credentials.json` so `compartmentId` is the same compartment as the subnet.

**SSH times out after instance launch**
OCI instances can take 60–90 seconds after reaching `RUNNING` state before SSH is ready. The script waits 20 seconds — if that's not enough, wait another minute and run:
```bash
./deploy.sh --cloud cloud.json --refresh fishing
```

**"Shape VM.Standard.E2.1.Micro not available"**
Always Free shapes are only available in your home region. Make sure `region` in `cloud.json` matches the home region you selected when creating your OCI account.

**"`oci` command not found"**
The OCI CLI was not installed or is not on your PATH. After installation, open a new terminal or run:
```bash
export PATH="$HOME/bin:$PATH"
```
(or wherever the installer placed the `oci` binary).
