# Deploying to AWS (EC2)

The deploy script provisions an EC2 `t2.micro` instance running Ubuntu 22.04, deploys your project, and serves it over **HTTPS via [sslip.io](https://sslip.io) + Caddy** — no domain purchase required.

For wasm projects, you can instead deploy to S3 object storage — no VM needed. See the [Wasm Object Storage](#wasm-object-storage-s3) section below.

---

## How HTTPS Works Without a Domain

[sslip.io](https://sslip.io) is a free public DNS service that resolves `1-2-3-4.sslip.io` to the IP `1.2.3.4`. This gives your EC2 instance a stable domain name that Let's Encrypt can issue a trusted certificate for.

The deploy script:
1. Deploys your app on its internal port (e.g. 4000)
2. Installs [Caddy](https://caddyserver.com/) on the VM
3. Configures Caddy to listen on `<ip-with-dashes>.sslip.io` (ports 80/443)
4. Caddy automatically obtains a Let's Encrypt certificate
5. Caddy reverse-proxies HTTPS traffic to your app

**Example:** EC2 IP `54.183.164.223` → URL `https://54-183-164-223.sslip.io`

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

## Step 1 — Install the AWS CLI

```bash
# macOS
brew install awscli

# Ubuntu/Debian
sudo apt-get install awscli
```

Verify: `aws --version`

---

## Step 2 — Create an IAM User

1. Go to **AWS Console → IAM → Users → Create user**
2. Username: `portfolio-deploy` (or any name)
3. **Permissions:** Attach the `AmazonEC2FullAccess` policy directly (for VM deploys), or `AmazonS3FullAccess` (for wasm object storage), or both
4. Click through to create the user

---

## Step 3 — Generate an Access Key

1. Open the user → **Security credentials** tab
2. **Access keys → Create access key**
3. Use case: **CLI**
4. Download `.csv` or copy the keys

---

## Step 4 — Create `aws-credentials.json`

Save your credentials as a JSON file (e.g. `~/aws-credentials.json`):

```json
{
  "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

The deploy script also accepts the `aws iam create-access-key` format:

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

## Step 5 — Add an Entry to `cloud.json`

```bash
cp cloud.json.template cloud.json
```

Example entry for Labyrinth (Node.js):

```json
{
  "labyrinth": {
    "repoUrl": "https://github.com/Siderskini/Labyrinth",
    "type": "node",
    "port": 4000,
    "provider": "aws",
    "region": "us-east-1",
    "authKey": "./aws-credentials.json"
  }
}
```

Example entry for Flowers (Ruby on Rails):

```json
{
  "flowers": {
    "repoUrl": "https://github.com/Siderskini/RubyOnRails/tree/main/Flowers",
    "type": "rails",
    "port": 3001,
    "provider": "aws",
    "region": "us-east-1",
    "authKey": "./aws-credentials.json"
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
| `authKey` | Relative or absolute path to your `aws-credentials.json` |

### Available Regions

Common Free Tier-eligible regions: `us-east-1` (N. Virginia), `us-west-2` (Oregon), `eu-west-1` (Ireland), `ap-southeast-1` (Singapore).

---

## Step 6 — Deploy

```bash
./deploy.sh --cloud cloud.json
```

The script will:

1. Delete and re-import the `portfolio-deploy` EC2 key pair using your current `~/.ssh/portfolio_deploy.pub` — this keeps the key in sync even after key rotation
2. Create a security group opening ports 22 (SSH), 80 (HTTP), and 443 (HTTPS)
3. Find the latest Ubuntu 22.04 AMI in your region
4. Launch a `t2.micro` instance tagged `portfolio-<id>` (or reuse/start an existing one)
5. Wait for SSH readiness
6. Run an Ansible playbook: install the runtime (Node/Ruby), clone the repo, start the app as a systemd service
7. Install Caddy and configure it for `https://<ip-with-dashes>.sslip.io`
8. Write the HTTPS URL to `.env.local`

Re-running deploy never creates a duplicate VM — instances are found by their `Name` tag.

---

## Wasm Object Storage (S3)

For `type: "wasm"` projects, adding a `bucket` field deploys to S3 instead of a VM:

```json
{
  "fishing": {
    "repoUrl": "https://github.com/Siderskini/LearningGo/tree/main/fishing/web",
    "type": "wasm",
    "provider": "aws",
    "region": "us-east-1",
    "authKey": "./aws-credentials.json",
    "bucket": "my-portfolio-fishing-bucket"
  }
}
```

The bucket name must be globally unique across all AWS accounts. The script creates the bucket if it doesn't exist, sets public-read access, and uploads all files with correct Content-Types.

The IAM user needs `AmazonS3FullAccess` for this path.

---

## What URL to Use

After deploy, the console prints:

```
[deploy]  labyrinth    https://54-183-164-223.sslip.io
```

This is also written to `.env.local`:

```
LABYRINTH_URL=https://54-183-164-223.sslip.io
```

The portfolio reads this at startup and uses it for the "Launch Demo" button.

---

## Refreshing (Pull Latest Code + Restart)

```bash
./deploy.sh --cloud cloud.json --refresh labyrinth
```

For VM projects: SSHes in, runs `git pull`, and restarts the service via Ansible. Caddy is not reinstalled.

For wasm+S3: re-clones/pulls the repo locally and re-uploads all files to the bucket.

---

## Troubleshooting

**"Unable to locate credentials"**
Check that your `aws-credentials.json` contains valid keys and the path in `cloud.json` is correct.

**"UnauthorizedOperation" on run-instances**
Your IAM user needs `AmazonEC2FullAccess`. Attach it in **IAM → Users → your user → Permissions**.

**SSH "Permission denied (publickey)"**
The EC2 key pair was out of sync with your local key. The deploy script now deletes and re-imports the key pair on every run. Delete the stale key pair manually first:
```bash
aws ec2 delete-key-pair --key-name portfolio-deploy --region <your-region>
```
Then redeploy.

**SSH times out after instance creation**
The instance may still be initializing. The script waits for `instance-running` state, but sshd can take another 30–60 seconds. Re-run `--refresh <id>` once the instance is fully up.

**Caddy fails to obtain a certificate**
Port 80 must be publicly reachable for the Let's Encrypt HTTP-01 challenge. The security group opens port 80 automatically. On the VM: `sudo systemctl status caddy` and `sudo journalctl -u caddy -n 50`.

**App is reachable on its port but not via sslip.io**
Caddy reverse-proxies from the sslip.io hostname to `localhost:<port>`. Check: `sudo systemctl status caddy`.
