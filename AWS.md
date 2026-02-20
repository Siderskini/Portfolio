# Deploying to AWS (EC2)

The deploy script can provision an EC2 `t2.micro` instance running Ubuntu 22.04, deploy any project to it, and serve it over **HTTPS via [sslip.io](https://sslip.io) + Caddy** — no domain purchase required.

---

## How HTTPS Works Without a Domain

[sslip.io](https://sslip.io) is a free public DNS service that resolves hostnames like `1-2-3-4.sslip.io` to the IP `1.2.3.4`. This gives your EC2 instance a stable, real domain name that Let's Encrypt can issue a trusted certificate for.

The deploy script:
1. Deploys your app on its internal port (e.g. 4000)
2. Installs [Caddy](https://caddyserver.com/) on the VM
3. Configures Caddy to listen on `<ip-with-dashes>.sslip.io` (ports 80/443)
4. Caddy automatically obtains a Let's Encrypt certificate for that hostname
5. Caddy reverse-proxies HTTPS traffic to your app

**Example:** EC2 IP `54.183.164.223` → URL `https://54-183-164-223.sslip.io`

---

## Step 1 — Create an IAM User

1. Go to **AWS Console → IAM → Users → Create user**
2. Username: `portfolio-deploy` (or any name)
3. **Permissions:** Attach the `AmazonEC2FullAccess` policy directly
4. Click through to create the user

---

## Step 2 — Generate an Access Key

1. Open the user you just created → **Security credentials** tab
2. **Access keys → Create access key**
3. Use case: **CLI**
4. Click through and **Download `.csv`** or copy the keys

---

## Step 3 — Create `aws-credentials.json`

Save your credentials as a JSON file anywhere on your machine (e.g. `~/aws-credentials.json`):

```json
{
  "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

The deploy script also supports the format returned by `aws iam create-access-key`:

```json
{
  "AccessKey": {
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

> **Security:** Keep this file outside the portfolio repo. It is already listed in `.gitignore`.

---

## Step 4 — Install the AWS CLI

```bash
# macOS
brew install awscli

# Ubuntu/Debian
sudo apt-get install awscli

# Or download from:
# https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
```

Verify: `aws --version`

---

## Step 5 — Add an Entry to `cloud.json`

Copy `cloud.json.template` to `cloud.json` if you haven't already:

```bash
cp cloud.json.template cloud.json
```

Add an entry for the project you want to deploy on AWS:

```json
{
  "labyrinth": {
    "repoUrl": "https://github.com/Siderskini/Labyrinth",
    "type": "node",
    "port": 4000,
    "provider": "aws",
    "region": "us-east-1",
    "authKey": "/home/you/aws-credentials.json"
  }
}
```

### Fields

| Field | Description |
|---|---|
| `repoUrl` | GitHub repo URL. Use `/tree/branch/subdir` for a subdirectory. |
| `type` | `rails`, `node`, `wasm`, or `nextjs` |
| `port` | Internal port the app listens on |
| `provider` | `aws` |
| `region` | AWS region (e.g. `us-east-1`, `us-west-2`, `eu-west-1`) |
| `authKey` | Absolute or relative path to your `aws-credentials.json` |

### Available Regions

Common free-tier-eligible regions: `us-east-1` (N. Virginia), `us-west-2` (Oregon), `eu-west-1` (Ireland), `ap-southeast-1` (Singapore).

---

## Step 6 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

The script will:

1. Import `~/.ssh/portfolio_deploy.pub` as a key pair named `portfolio-deploy` in the region
2. Create a security group opening ports 22 (SSH), 80 (HTTP), and 443 (HTTPS)
3. Find the latest Ubuntu 22.04 AMI in your region
4. Launch a `t2.micro` instance tagged `portfolio-<id>`
5. Wait for the instance to reach running state
6. SSH in and run the project setup (installs Node/Ruby/Python, clones repo, starts app)
7. Install Caddy and configure it for `https://<ip-with-dashes>.sslip.io`
8. Write the HTTPS URL to `.env.local` so the portfolio's "Launch Demo" buttons link to it

**Re-running deploy never creates a duplicate VM** — instances are found by their `Name` tag.

---

## What URL to Use

After deploy, the console prints the URL:

```
[deploy]  labyrinth    https://54-183-164-223.sslip.io
```

This is also written to `.env.local`:

```
LABYRINTH_URL=https://54-183-164-223.sslip.io
```

The portfolio reads this at startup and uses it for the "Launch Demo" button on the Labyrinth card.

---

## Refreshing (Pull Latest Code + Restart)

To update the app on the VM without reprovisioning:

```bash
./deploy.sh --cloud cloud.json --refresh labyrinth
```

This SSHes in, runs `git pull`, and restarts the process. Caddy is not reinstalled.

After refreshing any cloud project, the script automatically syncs updated URLs to the portfolio VM (if the portfolio is also cloud-hosted on Azure).

---

## Instance Details

| Property | Value |
|---|---|
| Instance type | `t2.micro` (Free Tier eligible for 12 months) |
| OS | Ubuntu 22.04 LTS |
| SSH key | `~/.ssh/portfolio_deploy` (4096-bit RSA, auto-generated) |
| SSH user | `ubuntu` |
| VM name tag | `portfolio-<id>` |
| Security group | `portfolio-<id>-sg` |

---

## Troubleshooting

**"Unable to locate credentials"**
The script exports `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from your JSON file. If you see this error, check that your `aws-credentials.json` contains valid keys and the path in `cloud.json` is correct.

**"UnauthorizedOperation" on run-instances**
Your IAM user needs `AmazonEC2FullAccess`. Attach the policy in IAM → Users → your user → Permissions.

**Instance launched but SSH times out**
The instance may still be initializing. The script waits for `instance-running` state, but the SSH daemon can take another 30–60 seconds. Run `--refresh labyrinth` once the instance is fully up.

**Caddy fails to obtain a certificate**
Port 80 must be reachable from the internet for the Let's Encrypt HTTP-01 challenge. The security group opens port 80 automatically. If you see certificate errors, check that no other firewall (e.g. iptables) is blocking port 80 on the VM.

**App is reachable on port 4000 but not via sslip.io**
Caddy reverse-proxies from the sslip.io hostname on 443 to `localhost:4000`. If Caddy isn't running, SSH into the VM and check: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.
