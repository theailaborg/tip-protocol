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

---

## Before you start (every path)

1. **Install** the AWS CLI v2 (`brew install awscli`), plus for path A
   Terraform 1.5 or newer (`brew install hashicorp/tap/terraform`) and `python3`.
2. **Log in to AWS** as a user that can create IAM, KMS and S3 resources in our
   account. We use SSO with the profile `tip`:

   ```bash
   aws sso login --profile tip          # opens the browser; first time ever: aws configure sso
   export AWS_PROFILE=tip
   aws sts get-caller-identity --query Arn --output text
   ```

   The last command must print your identity
   (`arn:aws:sts::<account>:assumed-role/...`). `Token has expired` means run
   `aws sso login` again.

---

## A. One command (Terraform)

**1. Make a working folder for this bucket.** Terraform remembers what it
created in a `terraform.tfstate` file in the folder it runs in. One folder per
bucket: never reuse the repo's `infra/s3-media/` folder (it already tracks a dev
bucket, and changing its `bucket_name` would make Terraform try to replace that
bucket).

```bash
mkdir -p ~/tip-s3/rooverse && cd ~/tip-s3/rooverse
cp ~/tip-protocol/infra/s3-media/{*.tf,setup.sh,terraform.tfvars.example} .
cp terraform.tfvars.example terraform.tfvars
```

**2. Fill three values** in `terraform.tfvars`:

```hcl
bucket_name = "tip-rooverse-media-eu-west-2"   # globally unique
region      = "eu-west-2"                      # closest to the node
trust_mode  = "keys"                           # "ec2" for a node on EC2
```

**3. Set the browser origins**, or the script writes `*` into the bucket CORS
and the printed env block:

```bash
export TIP_CORS_ORIGINS=https://theailab.org,https://www.theailab.org,https://vp.theailab.org
```

**4. Run it:**

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

(`bucket_policy.json` — replace placeholders):

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
bucket).

Everything below happens in **our** AWS account, run by a Lab operator with
admin rights. The partner only receives the access key and four env values.

### C.0 Decide and set the variables

Pick the bucket the partner writes to. Sharing one of the founding nodes'
buckets is the norm (SS shares node 1's); the bucket's host is then already on
the classifier's download allow-list, so nothing changes there.

```bash
export PARTNER=rooverse                                   # short slug
export USER_NAME=tip-$PARTNER-node-media                  # e.g. tip-rooverse-node-media
export BUCKET=tip-mainnet-1-media-us-east-1               # the shared bucket
export REGION=us-east-1                                   # that bucket's region
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export KMS_KEY_ARN=$(aws s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID' --output text)
echo "$USER_NAME -> $BUCKET ($REGION), key $KMS_KEY_ARN"
```

The last line must print a full `arn:aws:kms:...:key/...`. If it prints `None`,
the bucket is not SSE-KMS and this is the wrong bucket.

### C.1 Create the IAM user

No console password, no group, no other policy:

```bash
aws iam create-user --user-name $USER_NAME \
  --tags Key=purpose,Value=tip-partner-node-media Key=partner,Value=$PARTNER
export USER_ARN=$(aws iam get-user --user-name $USER_NAME --query User.Arn --output text)
echo $USER_ARN      # arn:aws:iam::<ACCOUNT_ID>:user/tip-rooverse-node-media
```

### C.2 Give it exactly the node's permissions

The same three statements the node role has (B.3): objects under `media/`,
listing only that prefix, and the bucket's KMS key, usable only through S3 in
that region.

```bash
cat > /tmp/$USER_NAME-policy.json <<EOF
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
  --policy-name media-bucket-access --policy-document file:///tmp/$USER_NAME-policy.json
```

No KMS key-policy change is needed: the key policy's `EnableRootPermissions`
statement delegates key access to IAM, so the user policy above is enough.

### C.3 Let the user past the bucket policy

The bucket policy denies everyone except the node role, so the user's own
policy is not enough on its own. Add the user ARN to the **three** statements
that name the role. Download, edit, upload:

```bash
aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text \
  | python3 -m json.tool > /tmp/$BUCKET-policy.json
cp /tmp/$BUCKET-policy.json /tmp/$BUCKET-policy.before.json      # keep the original
```

In `/tmp/$BUCKET-policy.json`:

| statement (`Sid`) | change |
|---|---|
| `DenyDataAccessExceptNodeRole` | append `"$USER_ARN"` to the `aws:PrincipalArn` list in its condition (the list of who is **not** denied) |
| `AllowNodeRole` | turn `"Principal": {"AWS": "<role arn>"}` into `"Principal": {"AWS": ["<role arn>", "<user arn>"]}` |
| `AllowNodeRoleListMediaPrefix` | the same change to its `Principal` |

`DenyInsecureTransport` stays untouched. With every existing user added the
same way (SS's user is already in those three lists), the condition looks like:

```json
"aws:PrincipalArn": [
  "arn:aws:iam::<ACCOUNT_ID>:role/tip-mainnet-1-media-us-east-1-node-role",
  "arn:aws:iam::<ACCOUNT_ID>:root",
  "arn:aws:iam::<ACCOUNT_ID>:user/tip-ss-node-media",
  "arn:aws:iam::<ACCOUNT_ID>:user/tip-rooverse-node-media"
]
```

Then apply it and confirm the user is in all three statements:

```bash
aws s3api put-bucket-policy --bucket $BUCKET --policy file:///tmp/$BUCKET-policy.json
aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text | grep -o "user/$USER_NAME" | wc -l
```

```text
3
```

> **Terraform caveat.** The founding buckets were created by the Terraform
> module, which does not know about partner users. A later `terraform apply`
> on that bucket rewrites the bucket policy and silently removes every partner
> user. Before any re-apply, add the user ARNs to the module's
> `DenyDataAccessExceptNodeRole` / `AllowNodeRole*` principals, or redo C.3
> afterwards.

### C.4 Create the access key

```bash
aws iam create-access-key --user-name $USER_NAME > /tmp/$USER_NAME-key.json
python3 -c "import json;k=json.load(open('/tmp/$USER_NAME-key.json'))['AccessKey'];print(k['AccessKeyId'])"
```

The JSON holds `AccessKeyId` and `SecretAccessKey`. AWS shows the secret
**once**; store the file with the partner's other credentials (mode 0600, never
in a repo or chat) and delete the `/tmp` copies after C.6.

### C.5 Check the user can do exactly what the node needs, and nothing more

Use the new key in a throwaway profile, from any machine:

```bash
aws configure set aws_access_key_id     <AccessKeyId>     --profile $USER_NAME
aws configure set aws_secret_access_key <SecretAccessKey> --profile $USER_NAME
aws configure set region $REGION --profile $USER_NAME
P="--profile $USER_NAME"

echo test > /tmp/c5.txt
aws s3 cp /tmp/c5.txt s3://$BUCKET/media/c5-check-$PARTNER.txt $P     # upload: allowed
aws s3 cp s3://$BUCKET/media/c5-check-$PARTNER.txt - $P               # read: prints "test"
aws s3 ls s3://$BUCKET/media/ $P | head -3                             # list media/: allowed
aws s3 rm s3://$BUCKET/media/c5-check-$PARTNER.txt $P                 # delete: allowed
aws s3 cp /tmp/c5.txt s3://$BUCKET/outside-media.txt $P               # outside media/: must FAIL
aws s3 ls s3://$BUCKET/ $P                                             # list the root: must FAIL
```

Expected: the first four succeed (`upload:`, `test`, a few `media/...` lines,
`delete:`); the last two end in `An error occurred (AccessDenied)`. Then confirm
the bucket's own node is unaffected: its `/status` stays **All good** and
uploads through that node still work.

Remove the profile afterwards (`aws configure` has no delete, so edit
`~/.aws/credentials` and `~/.aws/config` and drop the `[$USER_NAME]` /
`[profile $USER_NAME]` blocks).

### C.6 Hand over

The partner's `.env` gets (in the bundle's `node.env` before zipping, or sent
on the same separate channel as the zip password):

```text
TIP_MEDIA_BACKEND=s3
TIP_MEDIA_S3_BUCKET=<BUCKET>
TIP_MEDIA_S3_REGION=<REGION>
TIP_MEDIA_S3_KMS_KEY_ID=<KMS_KEY_ARN>
AWS_ACCESS_KEY_ID=<AccessKeyId>
AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
```

Their side (recreate, upload one image, see it under `media/`) is
`DEPLOYMENT.md` step 7. Record in the partner's private notes: user name,
bucket, key id (not the secret), date issued.

### C.7 Rotate every 90 days, revoke at offboarding

Rotation, without downtime:

```bash
aws iam create-access-key --user-name $USER_NAME          # second key, deliver it
# partner swaps the two AWS_* lines and recreates the container; then:
aws iam update-access-key --user-name $USER_NAME --access-key-id <OLD_ID> --status Inactive
aws iam delete-access-key --user-name $USER_NAME --access-key-id <OLD_ID>
```

Revocation (partner leaves, or a key leaks): set the key `Inactive` at once,
then delete the key, the inline policy and the user, and remove the user ARN
from the three bucket-policy statements (C.3 in reverse). Media the partner
already uploaded stays in the bucket.

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

After deploying, verify the auth gate and the bucket posture from
**outside** the node first, then from the node itself.

### 1. The bucket rejects anonymous and HTTPS-less access

From any machine without credentials:

```bash
# HTTPS, no signature → 403
curl -sI "https://$BUCKET.s3.$REGION.amazonaws.com/media/aa/test.bin"
# Expect: HTTP/2 403

# HTTP at all → 403 from DenyInsecureTransport
curl -sI "http://$BUCKET.s3.$REGION.amazonaws.com/media/aa/test.bin"
# Expect: HTTP/2 403
```

### 2. The bucket rejects the wrong principal

From an AWS environment with credentials that are NOT the node role:

```bash
aws s3 ls "s3://$BUCKET/media/" --region "$REGION"
# Expect: An error occurred (AccessDenied)
```

### 3. The node can read/write

From the running TIP node (or assume the role locally):

```bash
# Upload a test image through the TIP API
curl -X POST http://localhost:8080/v1/media/upload \
  -H "X-Media-Mime: image/png" \
  -H "X-Signer-TipId: tip://id/US-..." \
  -H "X-Signer-Signature: <hex>" \
  -H "X-Timestamp: $(date +%s%3N)" \
  --data-binary @test.png

# → 201 with { media_id, content_hash, mime, size, ... }

# Confirm the object landed:
aws s3api head-object \
  --bucket "$BUCKET" \
  --key "media/$(echo $MEDIA_ID | cut -c1-2)/$(echo $MEDIA_ID | cut -c3-).bin" \
  --region "$REGION"
```

### 4. A reviewer can fetch via a presigned URL

```bash
# As an authorized reviewer (signed MEDIA_ACCESS challenge):
curl -i "http://localhost:8080/v1/content/$CTID/media/0" \
  -H "X-Requester-TipId: tip://id/US-..." \
  -H "X-Signature: <hex>" \
  -H "X-Timestamp: $(date +%s%3N)"

# → 200 with { presigned_url, expires_at, ... }

# Use the URL:
curl -o fetched.png "$PRESIGNED_URL"
# Expect: 200, image bytes.

# After 300s, retry:
sleep 310 && curl -i "$PRESIGNED_URL"
# Expect: 403, signature expired.
```

### 5. App-side retention is wired

Set the env override and run a one-off sweep on a non-prod node:

```bash
TIP_MEDIA_RETENTION_SWEEP_INTERVAL_MS=60000 \
  node -e "require('./src/index')"
# Tail logs: "Media retention swept: content { ... } orphan { ... }"
```

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

- **CloudWatch metric `4xxErrors` on the bucket** — sudden spike usually
  means a signature contract changed in the node code or the IAM role
  drifted.
- **`AllRequests` count** — sanity check that the retention sweep isn't
  thrashing (steady-state should be ≈ traffic to the API).
- **KMS key throttling** — if you see `ThrottlingException`,
  `BucketKeyEnabled` should make this near-impossible, but it's worth
  alarming.
- **App log line "Media retention swept: …"** — confirms the sweep is
  running. Absence for >24h is a signal something's stuck.

## When something breaks

| Symptom | Likely cause |
|---|---|
| `AccessDenied` on PUT from node | KMS key policy missing the node role, or wrong `kms:ViaService` |
| `AccessDenied` on GET via presigned URL | Object encrypted with a key the role can't decrypt (e.g. someone wrote directly without SSE-KMS — shouldn't happen via the app) |
| `403 SignatureDoesNotMatch` on presigned URL | Clock skew on the node ≥ 15 minutes |
| `404 NoSuchKey` after a successful PUT | Eventual consistency — almost never in current S3, but possible on cross-region replication |
| Sweep deletes too aggressively | Cross-check `MEDIA_RETENTION.*` constants in `protocol-constants.js` vs `genesis.js` payload — divergence means the sweep is running on different windows than expected |
