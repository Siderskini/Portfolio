# Deploying to OCI (Oracle Cloud Infrastructure)

OCI is well-suited for this portfolio for two reasons:
- **Always Free VMs:** `VM.Standard.A1.Flex` (ARM, 1 OCPU / 6 GB RAM) is permanently free — no 12-month limit
- **Always Free Object Storage:** Great for wasm projects — no VM needed at all

The deploy script can either host your project on a VM with HTTPS via [sslip.io](https://sslip.io) + Caddy, or upload a wasm project directly to an OCI Object Storage bucket.

---

## Instance Details (VM Deployments)

| Property | Value |
|---|---|
| Shape | `VM.Standard.A1.Flex` (ARM, 1 OCPU / 6 GB RAM) |
| OS | Oracle Linux 9 |
| SSH key | `~/.ssh/portfolio_deploy` (4096-bit RSA, auto-generated) |
| SSH user | `opc` |
| Display name | `portfolio-<id>` |

> **Always Free:** Oracle Cloud offers 4 OCPU + 24 GB RAM total for `VM.Standard.A1.Flex`, permanently free in your home region. See https://www.oracle.com/cloud/free/ for current limits.

> **ARM architecture:** `VM.Standard.A1.Flex` is ARM-based. The Ansible playbook installs Oracle Linux 9 packages via dnf and compiles Ruby via rbenv. This is handled automatically — no action needed.

> **SSH user is `opc`**, not `ubuntu`. Use `ssh -i ~/.ssh/portfolio_deploy opc@<ip>` to connect.

---

## How HTTPS Works Without a Domain

[sslip.io](https://sslip.io) is a free public DNS service that resolves `132-145-100-50.sslip.io` to the IP `132.145.100.50`. This gives your OCI instance a stable domain name that Let's Encrypt can issue a trusted certificate for.

> **OCI firewall is manual:** Unlike AWS, Azure, and GCP, OCI security list rules must be opened manually in the Console before deploying (see Step 5). The deploy script cannot modify security rules without replacing the entire list.

---

## OCI Auth: Why It's Different

OCI's CLI uses `~/.oci/config` rather than a single JSON credentials file. The deploy script also needs a **compartment OCID** and a **subnet OCID** that cannot be derived from the config file alone.

For this reason, `authKey` points to a small JSON file you create:

```json
{
  "configFile":    "/home/you/.oci/config",
  "profile":       "DEFAULT",
  "compartmentId": "ocid1.compartment.oc1..<your-compartment-ocid>",
  "subnetId":      "ocid1.subnet.oc1..<your-subnet-ocid>"
}
```

For **wasm object storage** deployments, `subnetId` is not required (no VM is provisioned):

```json
{
  "configFile":    "/home/you/.oci/config",
  "profile":       "DEFAULT",
  "compartmentId": "ocid1.compartment.oc1..<your-compartment-ocid>"
}
```

---

## Step 1 — Create an OCI Account

Sign up at https://www.oracle.com/cloud/free/ — the Always Free tier is permanent and does not require a credit card upgrade.

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

This creates `~/.oci/config` and generates an API signing key pair. During setup you'll need:
- **User OCID:** Console → top-right profile menu → User Settings → OCID
- **Tenancy OCID:** Console → top-right profile menu → Tenancy → OCID
- **Region:** your home region (e.g. `us-ashburn-1`)

After setup, upload the generated public key to OCI:

1. **Identity & Security → Users → your user → API Keys → Add API Key**
2. Choose **Paste Public Key** and paste the contents of `~/.oci/oci_api_key_public.pem`

Verify:

```bash
oci iam user get --user-id <your-user-ocid>
```

---

## Step 3 — Find Your Compartment OCID

1. Go to **Identity & Security → Compartments**
2. Click on your target compartment (or use the root compartment, which has the same OCID as your tenancy)
3. Copy the **OCID**

---

## Step 4 — Set Up a VCN and Find Your Subnet OCID

*(Skip this step for wasm object storage — no VCN needed.)*

The VM must be launched into a public subnet. OCI does not always create a default VCN.

### If you have no VCN

1. Go to **Networking → Virtual Cloud Networks**
2. Click **Start VCN Wizard → Create VCN with Internet Connectivity**
3. Fill in a VCN name and select your compartment; leave CIDR defaults
4. Click **Next → Create**

This creates the VCN, internet gateway, and a public subnet automatically.

### Find the subnet OCID

1. **Networking → Virtual Cloud Networks** → click your VCN
2. Click **Subnets** → click the **public** subnet
3. Copy the **OCID**

> Use the **public** subnet — it has internet access via the internet gateway, required for the VM to be reachable and for Caddy to obtain a certificate. The deploy script validates this and fails fast if the subnet is private.

---

## Step 5 — Open Ports in Security Rules

*(Required for VM deployments. Skip for wasm object storage.)*

**This must be done before deploying.** Open these four inbound ports from `0.0.0.0/0`:

| Port | Protocol | Purpose |
|---|---|---|
| `22` | TCP | SSH deploy access |
| `80` | TCP | Caddy HTTP (Let's Encrypt challenge) |
| `443` | TCP | Caddy HTTPS |
| your app port (e.g. `8080`) | TCP | App internal port |

1. **Networking → Virtual Cloud Networks → your VCN → Security Lists**
2. Click on your security list (e.g. `Default Security List for...`)
3. **Add Ingress Rules** — add one rule per port using the table above
4. Click **Add Ingress Rules**

Also ensure outbound access is allowed (default security lists usually allow all egress).

---

## Step 6 — Create `oci-credentials.json`

For VM deployments:

```json
{
  "configFile":    "/home/you/.oci/config",
  "profile":       "DEFAULT",
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subnetId":      "ocid1.subnet.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

For wasm object storage only:

```json
{
  "configFile":    "/home/you/.oci/config",
  "profile":       "DEFAULT",
  "compartmentId": "ocid1.compartment.oc1..aaaaaaaaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

Save it anywhere (e.g. `./oci-credentials.json`). It is already listed in `.gitignore`.

> `compartmentId` must match the compartment of the subnet. If they differ, the deploy script warns and uses the subnet's compartment.

---

## Step 7 — Add an Entry to `cloud.json`

```bash
cp cloud.json.template cloud.json
```

### VM Deployment

```json
{
  "flowers": {
    "repoUrl": "https://github.com/Siderskini/RubyOnRails/tree/main/Flowers",
    "type": "rails",
    "port": 3001,
    "provider": "oci",
    "region": "us-ashburn-1",
    "authKey": "./oci-credentials.json"
  }
}
```

### Wasm Object Storage (Recommended for Fishing)

```json
{
  "fishing": {
    "repoUrl": "https://github.com/Siderskini/LearningGo/tree/main/fishing/web",
    "type": "wasm",
    "provider": "oci",
    "region": "us-ashburn-1",
    "authKey": "./oci-credentials.json",
    "bucket": "bucket-portfolio"
  }
}
```

With `bucket` set, no VM is provisioned. The deploy script clones the repo locally, uploads all files to OCI Object Storage with correct Content-Types, and sets the bucket to public read. The bucket is created automatically if it doesn't exist.

To force VM hosting instead:
```bash
./deploy.sh --cloud cloud.json --vm
```

### Fields

| Field | Description |
|---|---|
| `repoUrl` | GitHub repo URL. Use `/tree/branch/subdir` for a subdirectory. |
| `type` | `rails`, `node`, `wasm`, or `nextjs` |
| `port` | Internal app port (ignored for wasm+bucket) |
| `provider` | `oci` |
| `region` | OCI region identifier (must be your **home region** for Always Free shapes) |
| `authKey` | Relative or absolute path to your `oci-credentials.json` |
| `bucket` | *(wasm only)* Object Storage bucket name — triggers storage deployment instead of VM |

### OCI Regions

| Region | Identifier |
|---|---|
| US East (Ashburn) | `us-ashburn-1` |
| US West (Phoenix) | `us-phoenix-1` |
| UK South (London) | `uk-london-1` |
| Germany Central (Frankfurt) | `eu-frankfurt-1` |
| Japan East (Tokyo) | `ap-tokyo-1` |
| Australia East (Sydney) | `ap-sydney-1` |

Always Free `VM.Standard.A1.Flex` instances must be in your **home region**.

---

## Step 8 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

**For VM deployments**, the script will:

1. Read the OCI config file and profile from your `oci-credentials.json`
2. Validate subnet/network prerequisites (public subnet, default route to internet gateway, security list ports)
3. Find the latest Oracle Linux 9 image for ARM in your region
4. Find the first availability domain in the region
5. Launch a `VM.Standard.A1.Flex` instance named `portfolio-<id>` (or reuse/start an existing stopped one)
6. Wait for SSH readiness (can take 60–90 seconds after `RUNNING` state)
7. Run an Ansible playbook: install runtime via dnf + rbenv/nvm, clone repo, start app as a systemd service
8. Install Caddy and configure it for `https://<ip-with-dashes>.sslip.io`
9. Write the HTTPS URL to `.env.local`

**For wasm+bucket deployments**, steps 1–9 are replaced by: clone repo locally → upload files to Object Storage → write the public URL to `.env.local`.

Re-running deploy never creates a duplicate instance — instances are looked up by display name and reused.

---

## What URL to Use

After a VM deploy:
```
[deploy]  flowers    https://132-145-100-50.sslip.io
```

After an object storage deploy:
```
[deploy]  fishing    https://objectstorage.us-ashburn-1.oraclecloud.com/n/<namespace>/b/<bucket>/o/index.html
```

Both are written to `.env.local` and used by the portfolio's "Launch Demo" buttons.

---

## Refreshing (Pull Latest Code + Restart)

```bash
./deploy.sh --cloud cloud.json --refresh fishing
```

For VM projects: SSHes in (`opc` user), runs `git pull`, restarts the systemd service. The instance is not reprovisioned.

For wasm+bucket: re-clones/pulls the repo locally and re-uploads all files to the bucket.

---

## Troubleshooting

**"App is unreachable" / Caddy certificate error**
Almost always caused by missing security list rules. Double-check that ports 22, 80, 443, and your app port are all open from `0.0.0.0/0` (Step 5). On the VM: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.

**"OCI instance has no public IP"**
Your subnet is private (`prohibit-public-ip-on-vnic=true`) or has no internet gateway route. Use a public subnet with a default route to an Internet Gateway.

**Route table warning during deploy**
The subnet's route table has no default route to an Internet Gateway. In **Networking → VCNs → your VCN → Route Tables**, verify the subnet's route table has `Destination: 0.0.0.0/0, Target: Internet Gateway`.

> If OCI shows "Rules in the route table must use private IP as a target", you're editing the Internet Gateway's ingress route table, not the subnet route table. Go back to the VCN's **Route Tables** list.

**"`compartmentId` or `subnetId` not found" error**
Missing fields in `oci-credentials.json`. Check spelling — they are case-sensitive.

**compartmentId vs subnet compartment mismatch**
The deploy script warns if your `compartmentId` doesn't match the subnet's compartment, and switches to the subnet's compartment automatically. Update `oci-credentials.json` to avoid the warning.

**"Shape VM.Standard.A1.Flex not available"**
Always Free ARM shapes are only available in your home region. Make sure `region` in `cloud.json` matches the home region you selected when creating your OCI account.

**SSH times out after instance launch**
OCI instances can take 60–90 seconds after reaching `RUNNING` before SSH is ready. The script waits 20 seconds — if that's not enough, run:
```bash
./deploy.sh --cloud cloud.json --refresh <id>
```

**"`oci` command not found"**
Open a new terminal after installation, or:
```bash
export PATH="$HOME/bin:$PATH"
```

**"Authorization failed or requested resource not found"**
Check: API key was uploaded to OCI (Step 2), `compartmentId` is correct, `subnetId` exists in the correct region, and the profile in `configFile` matches.
