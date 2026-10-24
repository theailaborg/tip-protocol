# Prod S3 setup for TIP media

When someone uploads an image or video through a node, the node stores the file.
By default it writes to its own disk (`TIP_MEDIA_BACKEND=fs`). In production the
file goes to Amazon S3 instead: private, encrypted with our own KMS key, and the
classifier fetches it through a short-lived signed link. This guide sets that up.

Whatever the path, the node ends up with these lines in its `.env`:

```text
TIP_MEDIA_BACKEND=s3
TIP_MEDIA_S3_BUCKET=<bucket name>
TIP_MEDIA_S3_REGION=<bucket region>
TIP_MEDIA_S3_KMS_KEY_ID=<KMS key ARN>
```

and its permission to use the bucket comes from **one** of two places:

- an **instance role** attached to its EC2 server: nothing secret in `.env`
  (our mainnet nodes);
- an **access key** of a dedicated IAM user, as two more lines
  `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `.env`: for a node that is not
  on EC2 (a Mac, bare metal, another cloud). It is a long-lived secret, so it is
  scoped to the bucket's `media/` folder only and rotated every 90 days.

---

## Pick a path

| path | use it when | it creates | you get | the node's `.env` gets |
|---|---|---|---|---|
| **A. One command** (Terraform, `setup.sh`) | a **new** bucket, the normal way | bucket, KMS key, bucket policy, and either an EC2 role (`trust_mode=ec2`) or an IAM user with a key (`trust_mode=keys`) | the env block printed at the end; with `ec2` also an instance-profile name to attach | the four lines; with `keys` also the two `AWS_*` lines |
| **B. By hand** (console / CLI) | a new bucket for an EC2 node, without Terraform | the same as A with `ec2`, one resource at a time | the same values, collected as you go | the four lines |
| **C. Share an existing Lab bucket** | a partner node off EC2 that should write into one of our buckets (how the SS node runs) | only an IAM user, its policy and its key; the bucket already exists | an access key | the four lines of that bucket plus the two `AWS_*` lines |

Mainnet nodes 1-3 were built with A (`ec2`). SS uses C on node 1's bucket. For a
new partner off EC2, A with `trust_mode=keys` gives them **their own** bucket in
the region they choose, which avoids editing a founding node's bucket policy; C
is the quicker option when sharing is fine. With A, tell the classifier team the
new bucket host so it may download from it; with C nothing changes there.

### Where each command runs

| what | machine | directory |
|---|---|---|
| path A | a Lab operator's laptop with the repo checked out | step 1 from the repo root; every later step in the bucket's own folder `~/tip-s3/<partner>` (step 1 creates it) |
| path B | a Lab operator's laptop | any folder; the JSON files it writes (`trust_ec2.json`, `node_policy.json`, `bucket_policy.json`) land there |
| path C | a Lab operator's laptop | any folder, **one terminal** for all of C.0 to C.7 (the steps share variables; C.0 makes its own private work folder, no repo needed) |
| putting the values in `.env` | the node host | `~/tip-protocol/.env`, then `cd ~/tip-protocol && sudo docker compose up -d --force-recreate tip-node` |
| smoke tests 1 and 2 | a Lab operator's laptop | any folder |
| smoke tests 3 and 4 | the VP app or extension; the log check on the node host | `~/tip-protocol` |
| smoke test 5 | the node host | `~/tip-protocol` |

---

## Before you start (every path)

1. **Install** the AWS CLI v2 (`brew install awscli`), plus for path A
   Terraform 1.5 or newer (`brew install hashicorp/tap/terraform`) and `python3`.
2. **Log in to AWS** as a user that can create IAM, KMS and S3 resources in our
   account. We use SSO with the profile `tip`:

   *Run on: your laptop, any folder.*

   ```bash
   aws sso login --profile tip
   export AWS_PROFILE=tip
   aws sts get-caller-identity --query Arn --output text
   ```

   (`aws sso login` opens the browser; the very first time on a machine, run
   `aws configure sso` instead.) On a Mac, also run `setopt interactivecomments`
   once per terminal, so the `#` comment lines in the commands below paste
   cleanly into zsh. The last command must print your identity
   (`arn:aws:sts::<account>:assumed-role/...`). `Token has expired` means run
   `aws sso login` again.

---

## A. One command (Terraform)

**1. Make a working folder for this bucket.** Terraform remembers what it
created in a `terraform.tfstate` file in the folder it runs in. One folder per
bucket: never reuse the repo's `infra/s3-media/` folder (it already tracks a dev
bucket, and changing its `bucket_name` would make Terraform try to replace that
bucket).

Run on your laptop, **from the root of your `tip-protocol` checkout**:

```bash
mkdir -p ~/tip-s3/rooverse
cp infra/s3-media/{*.tf,setup.sh,terraform.tfvars.example} ~/tip-s3/rooverse/
cd ~/tip-s3/rooverse
cp terraform.tfvars.example terraform.tfvars
ls
```

This makes an empty folder for this bucket, copies the Terraform files and
`setup.sh` into it, moves there, and makes your own settings file from the
template. `ls` must show `main.tf`, `outputs.tf`, `setup.sh`,
`terraform.tfvars`, `terraform.tfvars.example`, `variables.tf`, `versions.tf`.
Every later step of path A runs in `~/tip-s3/rooverse`.

**2. Fill three values** in `terraform.tfvars`:

```hcl
bucket_name = "tip-rooverse-media-eu-west-2"   # globally unique
region      = "eu-west-2"                      # closest to the node
trust_mode  = "keys"                           # see the table below
```

`trust_mode` answers one question: **how will the node prove to AWS that it
may use this bucket?** It only changes the node's credentials; the bucket, the
key and the permissions are identical in every mode.

| `trust_mode` | pick it when the node runs | the node proves itself with | what you hand the node | we use it for |
|---|---|---|---|---|
| `ec2` | on an AWS EC2 server | the server's **instance role**, attached once in the EC2 console; AWS gives the node short-lived credentials automatically | nothing secret, only the four `TIP_MEDIA_*` lines | mainnet nodes 1-3 |
| `keys` | anywhere else (a Mac, bare metal, another cloud) | an **access key** of an IAM user that can only touch this bucket's `media/` | the four lines plus `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (rotate every 90 days) | the test cluster's dev bucket; the choice for a partner off EC2 |
| `external` | anywhere else, when a long-lived key is not acceptable | an **X.509 certificate** exchanged for short-lived credentials (IAM Roles Anywhere); needs the `aws_signing_helper` program on the node host | two certificate files and an AWS profile on the node host | not used |
| `irsa` | as a Kubernetes (EKS) pod | the pod's service account | a service-account annotation | not used |

For TIP the choice is simply: **`ec2` if the node is on EC2, otherwise
`keys`.** The template file defaults to `keys`; the module's own default is `ec2`.

**3. Set the browser origins**, or the script writes `*` into the bucket CORS
and the printed env block:

```bash
export TIP_CORS_ORIGINS=https://theailab.org,https://www.theailab.org,https://vp.theailab.org
```

**4. Run it:**

*Run on: your laptop, in the bucket's folder `~/tip-s3/<partner>` (path A step 1).*

```bash
./setup.sh
```

What it does, in order:

1. checks Terraform and the AWS CLI are installed and the three values are set;
2. checks your AWS login (tries `aws sso login` once if the token expired) and
   prints `> AWS identity: ...`;
3. runs `terraform init` and `terraform apply`, which creates: the bucket with
   public access blocked, versioning, encryption by the new KMS key, CORS, a
   lifecycle rule and a bucket policy that denies everyone but the node; the KMS
   key and its alias; and the node's identity, which is an IAM role plus instance
   profile for `ec2`, or an IAM user with a scoped policy and an access key for
   `keys`; plus a CloudWatch alarm if the key is used by anyone else;
4. prints the env block and the one wiring step for the mode.

It ends like this (`keys` mode):

```text
> DONE. Add this to the node's .env:
--------------------------------------------------------------
TIP_MEDIA_BACKEND=s3
TIP_MEDIA_S3_BUCKET=tip-rooverse-media-eu-west-2
TIP_MEDIA_S3_REGION=eu-west-2
TIP_MEDIA_S3_KMS_KEY_ID=arn:aws:kms:eu-west-2:<account>:key/<id>
TIP_CORS_ORIGINS=https://theailab.org,https://www.theailab.org,https://vp.theailab.org
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
--------------------------------------------------------------
```

With `ec2` there are no `AWS_*` lines; instead it prints an instance-profile
name to attach to the node's EC2 instance (console: EC2, the instance, Actions,
Security, Modify IAM role).

**5. Use the output.** Put the printed lines into the node's `.env` (for a
partner: the bundle's `node.env` before zipping; `TIP_CORS_ORIGINS` is already
there). Treat the `AWS_*` lines as a password.

**6. Keep the folder.** Its `terraform.tfstate` is how the bucket is changed or
rotated later, and in `keys` mode it also contains the secret key, so store the
folder with our other credentials, never in a repo. Rotate the key every 90 days
from that folder:

```bash
terraform apply -replace='aws_iam_access_key.media_node[0]'
terraform output -raw node_access_key_id ; terraform output -raw node_secret_access_key
```

then hand the node the two new lines. Verify with **§ Smoke test** below.

---

## B. AWS Console / CLI path

Run on a Lab operator's laptop, in one terminal, from an empty folder
(`mkdir -p ~/tip-s3/<name> && cd ~/tip-s3/<name>`): the steps share
variables and write their JSON files into the current folder.

If you're standing up a one-off bucket or evaluating, the steps below
provision the same resources without Terraform.

Variables used throughout:

```bash
export BUCKET=tip-media-prod-uswest2
export REGION=us-west-2
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ROLE_NAME=$BUCKET-node-role
```

### B.1 Create the KMS key

```bash
aws kms create-key \
  --region "$REGION" \
  --description "TIP media SSE-KMS for s3://$BUCKET" \
  --key-usage ENCRYPT_DECRYPT \
  --customer-master-key-spec SYMMETRIC_DEFAULT \
  --query KeyMetadata.KeyId --output text > .kms_key_id
KMS_KEY_ID=$(cat .kms_key_id)
KMS_KEY_ARN=arn:aws:kms:$REGION:$ACCOUNT_ID:key/$KMS_KEY_ID

aws kms enable-key-rotation --region "$REGION" --key-id "$KMS_KEY_ID"

aws kms create-alias \
  --region "$REGION" \
  --alias-name "alias/tip-media-$BUCKET" \
  --target-key-id "$KMS_KEY_ID"
```

### B.2 Create the bucket

```bash
aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION"

aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-ownership-controls \
  --bucket "$BUCKET" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'

aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration "{
    \"Rules\": [{
      \"ApplyServerSideEncryptionByDefault\": {
        \"SSEAlgorithm\": \"aws:kms\",
        \"KMSMasterKeyID\": \"$KMS_KEY_ARN\"
      },
      \"BucketKeyEnabled\": true
    }]
  }"

# Lifecycle: abort stuck MPUs (7d) + app-side-retention backstop (90d).
aws s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET" \
  --lifecycle-configuration "{
    \"Rules\": [
      {
        \"ID\": \"abort-stuck-multipart\",
        \"Status\": \"Enabled\",
        \"Filter\": {},
        \"AbortIncompleteMultipartUpload\": {\"DaysAfterInitiation\": 7}
      },
      {
        \"ID\": \"media-backstop-deletion\",
        \"Status\": \"Enabled\",
        \"Filter\": {\"Prefix\": \"media/\"},
        \"Expiration\": {\"Days\": 90}
      }
    ]
  }"
```

Allow browser uploads (CORS). The VP app and the extension upload straight from
the browser to presigned S3 URLs and read each part's `ETag` back to finish the
upload; without this rule the browser blocks those requests and uploads from the
apps fail, while uploads from scripts still work. Same rule path A sets:

```bash
aws s3api put-bucket-cors --bucket "$BUCKET" --region "$REGION" --cors-configuration '{
  "CORSRules": [{
    "AllowedOrigins": ["https://theailab.org", "https://www.theailab.org", "https://vp.theailab.org"],
    "AllowedMethods": ["GET", "HEAD", "PUT"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["Content-Type", "Content-Length", "ETag"],
    "MaxAgeSeconds": 3600
  }]
}'
aws s3api get-bucket-cors --bucket "$BUCKET" --region "$REGION" --query 'CORSRules[0].[AllowedMethods,ExposeHeaders]' --output text
```

```text
GET	HEAD	PUT
Content-Type	Content-Length	ETag
```

The origins must match the node's `TIP_CORS_ORIGINS`; add any other browser
client's origin to both.

### B.3 Create the node IAM role

Trust policy (`trust_ec2.json`), so the EC2 instance can assume the role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

Create the role:

```bash
aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file://trust_ec2.json
ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text)
```

Attach the inline permission policy (`node_policy.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MediaObjectsRW",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::BUCKET/media/*"
    },
    {
      "Sid": "ListMediaPrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::BUCKET",
      "Condition": {
        "StringLike": { "s3:prefix": ["media/*", "media/"] }
      }
    },
    {
      "Sid": "UseMediaKmsKey",
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey"
      ],
      "Resource": "KMS_KEY_ARN"
    }
  ]
}
```

```bash
sed -i.bak "s|BUCKET|$BUCKET|g; s|KMS_KEY_ARN|$KMS_KEY_ARN|g" node_policy.json
aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "$BUCKET-node-policy" \
  --policy-document file://node_policy.json
```

Create the instance profile (the wrapper EC2 attaches the role through):

```bash
aws iam create-instance-profile --instance-profile-name "$ROLE_NAME"
aws iam add-role-to-instance-profile \
  --instance-profile-name "$ROLE_NAME" \
  --role-name "$ROLE_NAME"
```

### B.4 Update the KMS key policy

Add the node role to the key policy (`kms_policy.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootPermissions",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::ACCOUNT_ID:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowNodeRoleUseForEncryption",
      "Effect": "Allow",
      "Principal": { "AWS": "ROLE_ARN" },
      "Action": [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "kms:ViaService": "s3.REGION.amazonaws.com" }
      }
    }
  ]
}
```

```bash
sed -i.bak "s|ACCOUNT_ID|$ACCOUNT_ID|g; s|ROLE_ARN|$ROLE_ARN|g; s|REGION|$REGION|g" kms_policy.json
aws kms put-key-policy \
  --region "$REGION" \
  --key-id "$KMS_KEY_ID" \
  --policy-name default \
  --policy file://kms_policy.json
```

### B.5 Attach the bucket policy

(`bucket_policy.json`, replace the placeholders):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyEveryoneExceptNodeRole",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalArn": [
            "ROLE_ARN",
            "arn:aws:iam::ACCOUNT_ID:root"
          ]
        }
      }
    },
    {
      "Sid": "AllowNodeRole",
      "Effect": "Allow",
      "Principal": { "AWS": "ROLE_ARN" },
      "Action": [
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::BUCKET/media/*"
    },
    {
      "Sid": "AllowNodeRoleListMediaPrefix",
      "Effect": "Allow",
      "Principal": { "AWS": "ROLE_ARN" },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::BUCKET",
      "Condition": {
        "StringLike": { "s3:prefix": ["media/*", "media/"] }
      }
    }
  ]
}
```

```bash
sed -i.bak "s|BUCKET|$BUCKET|g; s|ROLE_ARN|$ROLE_ARN|g; s|ACCOUNT_ID|$ACCOUNT_ID|g" bucket_policy.json
aws s3api put-bucket-policy --bucket "$BUCKET" --policy file://bucket_policy.json
```

### B.6 Optional: VPC gateway endpoint

```bash
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-XXXXXXXX \
  --service-name "com.amazonaws.$REGION.s3" \
  --route-table-ids rtb-AAAAAAAA rtb-BBBBBBBB \
  --vpc-endpoint-type Gateway
```

---

## C. Share an existing Lab bucket (partner node off EC2)

A node off EC2 cannot have an instance role. Here, instead of creating a new
bucket (path A with `keys`), we give the node access to the `media/` folder of
one of our **existing** buckets through a dedicated IAM user with an access key.
This is how the SS Software node runs (user `tip-ss-node-media` on node 1's
bucket). Everything below happens in **our** AWS account; the partner only
receives the four `TIP_MEDIA_*` lines and the two `AWS_*` lines.

Validated end to end on the test cluster's bucket on 2026-10-24: user created,
access checks passed, a test node uploaded media with the key, then the user
was revoked and the bucket policy came back byte-identical.

### C.0 Log in, set the variables, make a private work folder

Run all of section C on a Lab operator's laptop, in **one terminal** (any
folder; nothing from the repo is needed). Every later step uses the variables
set here, so a new terminal means running C.0 again.

Log in first (see *Before you start*). Then pick the bucket the partner writes
to. Sharing a founding node's bucket keeps the classifier allow-list unchanged.

```bash
export AWS_PROFILE=tip
export PARTNER=rooverse
export USER_NAME=tip-$PARTNER-node-media
export BUCKET=tip-mainnet-1-media-us-east-1
export REGION=us-east-1
export AWS_REGION=$REGION
export KMS_KEY_ARN=$(aws s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID' --output text)
export W=$(mktemp -d) && chmod 700 "$W"
aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text > "$W/policy.original.json"
echo "$USER_NAME -> $BUCKET ($REGION), key $KMS_KEY_ARN"
```

`PARTNER` is the partner's short slug, `BUCKET` and `REGION` the shared bucket
and its region; `AWS_REGION` matters because our profile defaults to another
region; `W` is a private folder (never `/tmp` directly) that will hold the key
file. The last line must print a full `arn:aws:kms:<region>:<account>:key/<id>`. `None`
means the bucket is not SSE-KMS (wrong bucket); a KMS or S3 error usually means
`AWS_REGION` is not the bucket's region. Keep this terminal open: every later
step uses these variables.

### C.1 Create the IAM user

No console password, no group, no other policy:

```bash
aws iam create-user --user-name $USER_NAME \
  --tags Key=purpose,Value=tip-partner-node-media Key=partner,Value=$PARTNER --query User.UserName --output text
export USER_ARN=$(aws iam get-user --user-name $USER_NAME --query User.Arn --output text)
echo $USER_ARN
```

```text
tip-rooverse-node-media
arn:aws:iam::<account>:user/tip-rooverse-node-media
```

### C.2 Give it exactly the node's permissions

The same three statements the node role has: objects under `media/`, listing
only that prefix, and the bucket's KMS key, usable only through S3 in that region.

```bash
cat > "$W/user-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "MediaObjectsRW", "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::$BUCKET/media/*" },
    { "Sid": "ListMediaPrefix", "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::$BUCKET",
      "Condition": { "StringLike": { "s3:prefix": ["media/*", "media/"] } } },
    { "Sid": "UseMediaKmsKey", "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"],
      "Resource": "$KMS_KEY_ARN",
      "Condition": { "StringEquals": { "kms:ViaService": "s3.$REGION.amazonaws.com" } } }
  ]
}
EOF
aws iam put-user-policy --user-name $USER_NAME \
  --policy-name media-bucket-access --policy-document file://"$W/user-policy.json"
aws iam list-user-policies --user-name $USER_NAME --output text
```

Expect: `POLICYNAMES	media-bucket-access`.

No KMS key-policy change is needed: the key policy's `EnableRootPermissions`
statement hands key access to IAM, so the user policy above is enough.

### C.3 Let the user past the bucket policy

The bucket policy denies everyone except the bucket's own node, so the user's
policy alone is not enough. The user ARN must be added to the three statements
that name the node: `DenyDataAccessExceptNodeRole` (the list of who is **not**
denied), `AllowNodeRole` and `AllowNodeRoleListMediaPrefix`. This script does
exactly that and refuses if it cannot find all three:

```bash
aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text > "$W/policy.json"
python3 - "$W/policy.json" "$USER_ARN" <<'EOF'
import json, sys
path, user = sys.argv[1], sys.argv[2]
p = json.load(open(path)); done = []
def add(v):
    lst = v if isinstance(v, list) else [v]
    return lst if user in lst else lst + [user]
for s in p["Statement"]:
    if s["Sid"] == "DenyDataAccessExceptNodeRole":
        c = s["Condition"]["StringNotEqualsIfExists"]; c["aws:PrincipalArn"] = add(c["aws:PrincipalArn"]); done.append(s["Sid"])
    elif s["Sid"] in ("AllowNodeRole", "AllowNodeRoleListMediaPrefix"):
        s["Principal"]["AWS"] = add(s["Principal"]["AWS"]); done.append(s["Sid"])
assert len(done) == 3, f"expected 3 statements, found {done}"
json.dump(p, open(path, "w"), indent=2); print("added to:", ", ".join(done))
EOF
aws s3api put-bucket-policy --bucket $BUCKET --policy file://"$W/policy.json"
aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text | grep -o "user/$USER_NAME" | wc -l
```

```text
added to: DenyDataAccessExceptNodeRole, AllowNodeRole, AllowNodeRoleListMediaPrefix
3
```

> **Terraform caveat.** The founding buckets were created by the Terraform
> module, which does not know about partner users. A later `terraform apply`
> on that bucket rewrites the bucket policy and silently removes every partner
> user. Before any re-apply, add the user ARNs to the module's principals, or
> run C.3 again afterwards for each partner.

### C.4 Create the access key

```bash
( umask 077; aws iam create-access-key --user-name $USER_NAME > "$W/key.json" )
export KID=$(python3 -c "import json;print(json.load(open('$W/key.json'))['AccessKey']['AccessKeyId'])")
export KSEC=$(python3 -c "import json;print(json.load(open('$W/key.json'))['AccessKey']['SecretAccessKey'])")
echo "AccessKeyId $KID, secret ${#KSEC} characters"
```

AWS shows the secret **once**; it now lives only in `$W/key.json` (mode 0600)
and these two shell variables. Never paste it into chat or a ticket.

### C.5 Check the key does exactly what the node needs, and nothing more

A new key is rejected for a few seconds after creation, so wait for it first.
`as_user` runs a command with the partner key instead of your login, without
writing the key into `~/.aws`:

```bash
as_user() { env -u AWS_PROFILE AWS_ACCESS_KEY_ID=$KID AWS_SECRET_ACCESS_KEY=$KSEC AWS_REGION=$REGION aws "$@"; }
until as_user sts get-caller-identity --query Arn --output text 2>/dev/null; do sleep 5; done

echo test > "$W/c5.txt"
as_user s3 cp "$W/c5.txt" s3://$BUCKET/media/c5-check-$PARTNER.txt
as_user s3 cp s3://$BUCKET/media/c5-check-$PARTNER.txt -
as_user s3api head-object --bucket $BUCKET --key media/c5-check-$PARTNER.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId]' --output text
as_user s3 ls s3://$BUCKET/media/ | head -3
as_user s3 rm s3://$BUCKET/media/c5-check-$PARTNER.txt
as_user s3 cp "$W/c5.txt" s3://$BUCKET/outside-media.txt
as_user s3 ls s3://$BUCKET/
```

Expected: the identity line `arn:aws:iam::<account>:user/tip-<partner>-node-media`;
then 1 `upload:`, 2 `test`, 3 `aws:kms` with the same key ARN as C.0, 4 a few
`PRE xx/` lines, 5 `delete:`; 6 and 7 end in `AccessDenied ... no identity-based
policy allows`. Then confirm the bucket's own node still shows **All good** on
its `/status`.

Use the partner key, not your admin login, for any check that reads objects:
the bucket policy denies object reads even to our administrators, by design
(`403 Forbidden` on `head-object` as admin is expected).

### C.6 Hand over

These six lines go into the partner's `.env`, in the bundle's `node.env`
before zipping:

```bash
cat <<EOF
TIP_MEDIA_BACKEND=s3
TIP_MEDIA_S3_BUCKET=$BUCKET
TIP_MEDIA_S3_REGION=$REGION
TIP_MEDIA_S3_KMS_KEY_ID=$KMS_KEY_ARN
AWS_ACCESS_KEY_ID=$KID
AWS_SECRET_ACCESS_KEY=$KSEC
EOF
```

On their node that is all: replace `TIP_MEDIA_BACKEND=fs` with these lines and
recreate the container; `DEPLOYMENT.md` step 7 is their upload check. Record in
the partner's private notes: user name, bucket, key id (not the secret), date.
Then delete the work folder, which holds the secret:

```bash
rm -rf "${W:?}"; unset KSEC
```

### C.7 Rotate every 90 days, revoke at offboarding

Rotation, without downtime:

```bash
aws iam create-access-key --user-name $USER_NAME
# partner swaps the two AWS_* lines and recreates the container; then:
aws iam update-access-key --user-name $USER_NAME --access-key-id <OLD_ID> --status Inactive
aws iam delete-access-key --user-name $USER_NAME --access-key-id <OLD_ID>
```

Revocation (partner leaves, or the key leaks). **Order matters:** take the user
out of the bucket policy *before* deleting it. When an IAM user is deleted, AWS
rewrites its ARN inside bucket-policy principals into an internal id
(`AIDA...`), and the removal script below no longer finds it.

```bash
aws iam list-access-keys --user-name $USER_NAME --query 'AccessKeyMetadata[].AccessKeyId' --output text
aws iam update-access-key --user-name $USER_NAME --access-key-id <ID> --status Inactive

aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text > "$W/policy.json"
python3 - "$W/policy.json" "arn:aws:iam::<account>:user/$USER_NAME" <<'EOF'
import json, sys
path, user = sys.argv[1], sys.argv[2]
p = json.load(open(path)); done = []
def drop(v):
    lst = [x for x in (v if isinstance(v, list) else [v]) if x != user]
    return lst[0] if len(lst) == 1 else lst
for s in p["Statement"]:
    if s["Sid"] == "DenyDataAccessExceptNodeRole":
        c = s["Condition"]["StringNotEqualsIfExists"]; c["aws:PrincipalArn"] = drop(c["aws:PrincipalArn"]); done.append(s["Sid"])
    elif s["Sid"] in ("AllowNodeRole", "AllowNodeRoleListMediaPrefix"):
        s["Principal"]["AWS"] = drop(s["Principal"]["AWS"]); done.append(s["Sid"])
assert len(done) == 3, done
json.dump(p, open(path, "w"), indent=2); print("removed from:", ", ".join(done))
EOF
aws s3api put-bucket-policy --bucket $BUCKET --policy file://"$W/policy.json"
aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text | grep -o "user/$USER_NAME" | wc -l

aws iam delete-access-key  --user-name $USER_NAME --access-key-id <ID>
aws iam delete-user-policy --user-name $USER_NAME --policy-name media-bucket-access
aws iam delete-user        --user-name $USER_NAME
```

(`$W` is a fresh `mktemp -d` folder as in C.0.) Media the partner already
uploaded stays in the bucket.

---

## Wiring an EC2 node (path A with `ec2`, or path B)

Attach the instance profile to the node's EC2 instance (output
`instance_profile_name` from the Terraform module, or `$ROLE_NAME` from the CLI
path), then put the four values in the node's `.env` and recreate the container
(`docker compose up -d --force-recreate tip-node`). No AWS keys: the instance
role signs. Nodes with an access key (path A `keys`, path C) take the extra
`AWS_*` lines instead and need no attaching.

```
TIP_MEDIA_BACKEND=s3
TIP_MEDIA_S3_BUCKET=tip-media-prod-uswest2
TIP_MEDIA_S3_REGION=us-west-2
TIP_MEDIA_S3_KMS_KEY_ID=arn:aws:kms:us-west-2:111111111111:key/...
```

---

## Smoke test

Run these after any new bucket or any credential change. Tests 1 and 2 take a
minute from a laptop; tests 3 and 4 need the node already running on the bucket
and the VP app or extension; test 5 is a log check on the node host. All five
were run against the test cluster's bucket on 2026-10-24 with the results shown.

Tests 1 and 2 run on a Lab operator's laptop from any folder. Set the bucket
once in that terminal:

```bash
aws sso login --profile tip
export BUCKET=<bucket> REGION=<region> AWS_PROFILE=tip AWS_REGION=<region>
```

### 1. Strangers cannot get in

**Checks:** nobody on the internet can download a file without a valid signed
link, and plain `http://` is refused outright.

**How** (any machine, no login needed):

```bash
curl -sI "https://$BUCKET.s3.$REGION.amazonaws.com/media/aa/test.bin" | head -1
curl -sI "http://$BUCKET.s3.$REGION.amazonaws.com/media/aa/test.bin"  | head -1
```

**Pass:**

```text
HTTP/1.1 403 Forbidden
HTTP/1.1 403 Forbidden
```

**If not:** `200` means the bucket is public (public access block missing:
redo B.2 / rerun path A); a `200` or redirect on `http://` means the
`DenyInsecureTransport` statement is missing from the bucket policy.

### 2. Even our admins cannot read or write media

**Checks:** only the node's role or key may touch files. Our admin login can
list file names (Terraform needs that, and the names are only hashes) but must
not read or upload content.

**How** (as your admin login):

```bash
aws s3 ls s3://$BUCKET/media/ | head -2
aws s3api head-object --bucket $BUCKET --key media/aa/test.bin 2>&1 | tail -1
echo x > /tmp/x.txt && aws s3 cp /tmp/x.txt s3://$BUCKET/media/smoke-admin.txt 2>&1 | tail -1
```

**Pass:** the listing prints a few `PRE xx/` lines (allowed); the read ends in
`Forbidden`; the upload ends in `upload failed ... AccessDenied`.

**If not:** a successful read or upload means `DenyDataAccessExceptNodeRole`
is missing or lists the wrong principals; compare the bucket policy with B.5.

### 3. The node can store a file

**Checks:** the node can mint upload links with its credentials, the browser
can send the image straight to the bucket (this also proves the bucket CORS,
which only a browser exercises), and the stored file is encrypted with the
bucket's key.

**How:** in the VP app or extension pointed at the node, attach an image to a
new post. Behind the scenes: `upload-init` on the node, the image PUT straight
to a presigned S3 URL, then `upload-complete`. Then on the node host, in
`~/tip-protocol`:

```bash
sudo docker compose logs --since 10m tip-node | grep -ciE "AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch|s3.*error"
```

Optionally confirm the object with the node's own credentials (path C: the
partner key, as in C.5; admins cannot read objects):

*Run on: your laptop, in the same terminal where you set `BUCKET` and `REGION` above.*

```bash
MEDIA_ID=<media_id of the upload>
aws s3api head-object --bucket $BUCKET --key "media/${MEDIA_ID:0:2}/${MEDIA_ID:2}.bin" \
  --query '[ContentLength,ServerSideEncryption,SSEKMSKeyId]' --output text
```

**Pass:** the image shows as attached in the app; the error count is `0`; the
object reads `<size>  aws:kms  <the bucket's key ARN>`.

**If not:**

| symptom | cause |
|---|---|
| the app's upload fails, a script upload works | bucket CORS missing or the app's origin not in it (B.2 CORS step) |
| `AccessDenied` in the node log | the node's role or user is missing from the bucket policy (B.5 / C.3) or lacks the KMS permission (B.3 / C.2) |
| `InvalidAccessKeyId` / `SignatureDoesNotMatch` | wrong or deactivated `AWS_*` key in the node's `.env` (path C) |
| `410` on `POST /v1/media/upload` | expected: S3 nodes only take the presigned path |

### 4. The right people can open it, and links expire

**Checks:** when an allowed person opens the media, the node hands out a
short-lived signed link that works; it stops working after 5 minutes; anyone
else is refused. Allowed: the post's author, its assigned reviewer, a disputer,
a juror, an expert reviewer.

**How:** register the post from test 3 and open it in the app as its author:
the image must display. Copy the image's address from the browser (it points
at `<bucket>.s3.<region>.amazonaws.com/...X-Amz-...`), wait 5 minutes, open it
again. Then open the post as an unrelated account.

What the app receives from `GET /v1/content/<ctid>/media/0` (signed by the
requester):

```json
{ "ok": true, "status": 200, "data": {
  "media_id": "8e209f39...", "mime": "image/png",
  "presigned_url": "https://<bucket>.s3.<region>.amazonaws.com/media/8e/209f39....bin?X-Amz-...",
  "expires_at": "2026-10-24T16:15:44.155Z" } }
```

**Pass:** the image displays for the author; the copied link gives
`AccessDenied` after 5 minutes (`TIP_MEDIA_PRESIGN_TTL_SEC=300`); the unrelated
account gets `403 Not authorised to fetch this media`. Asked on a node that did
not receive the upload, the request is redirected (`307`) to the node that did,
because each node serves media from its own bucket; that is normal.

**If not:**

| symptom | cause |
|---|---|
| `410 media_unavailable` | the file was removed by retention, or never reached the bucket |
| the link still works after 5 minutes | `TIP_MEDIA_PRESIGN_TTL_SEC` set too high on that node |
| `303` with `available_at_node_id` | the origin node has not announced its `api_endpoint`, so the redirect has no target |

### 5. Old files get cleaned up

**Checks:** the node's retention job runs against S3 and removes media whose
retention period has ended.

**How** (on the node host, in `~/tip-protocol`):

```bash
sudo docker compose logs tip-node | grep "Media retention started"
sudo grep -h "Media retention swept" logs/node-1/*/info.log | tail -2
```

**Pass:**

```text
Media retention started: interval=21600000ms backend=s3
Media retention swept: content { deleted=.. skipped_active=.. ... } orphan { deleted=.. kept_referenced=.. ... }
```

The `swept` line appears every 6 hours; right after a restart there is none yet
(the first sweep waits the full interval), which is normal.

**If not:** `backend=fs` means `TIP_MEDIA_BACKEND` is not `s3`; `Media
retention sweep failed` in `error.log` usually means the node lost
`s3:ListBucket` on `media/`; `Media retention NOT started` means the backend
cannot list.

---

## Cost estimate (rough)

For a small federation (~50K media objects, ~500GB total):

| Item | Monthly |
|---|---|
| S3 storage (Standard, 500 GB) | ~$12 |
| S3 requests (1M GET + 100k PUT) | ~$1 |
| KMS requests (cut 99% by `BucketKeyEnabled`) | ~$0.10 |
| Customer-managed KMS key | $1 |
| Gateway VPC endpoint | $0 (no hourly charge) |

Most operators will be well under $20/month at this size.

---

## What to keep monitoring

- **CloudWatch metric `4xxErrors` on the bucket**: sudden spike usually
  means a signature contract changed in the node code or the IAM role
  drifted.
- **`AllRequests` count**: sanity check that the retention sweep isn't
  thrashing (steady-state should be ≈ traffic to the API).
- **KMS key throttling**: if you see `ThrottlingException`,
  `BucketKeyEnabled` should make this near-impossible, but it's worth
  alarming.
- **App log line "Media retention swept: …"**: confirms the sweep is
  running. Absence for >24h is a signal something's stuck.

## When something breaks

| Symptom | Likely cause |
|---|---|
| `AccessDenied` on PUT from node | KMS key policy missing the node role, or wrong `kms:ViaService` |
| `AccessDenied` on GET via presigned URL | Object encrypted with a key the role can't decrypt (e.g. someone wrote directly without SSE-KMS, which the app never does via the app) |
| `403 SignatureDoesNotMatch` on presigned URL | Clock skew on the node ≥ 15 minutes |
| `404 NoSuchKey` after a successful PUT | Eventual consistency: almost never in current S3, but possible on cross-region replication |
| Sweep deletes too aggressively | Cross-check `MEDIA_RETENTION.*` constants in `protocol-constants.js` vs `genesis.js` payload; divergence means the sweep is running on different windows than expected |
