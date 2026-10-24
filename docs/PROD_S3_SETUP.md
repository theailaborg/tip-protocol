# Prod S3 setup for TIP media

This guide deploys the S3 backend the TIP node uses for media bytes
(`media-storage-s3.js`). Two paths are documented:

- **A.** Terraform module (`infra/s3-media/`) — recommended for
  reproducible / version-controlled infra.
- **B.** AWS Console / CLI — for one-off setups where Terraform isn't
  available.
- **C.** A partner node that is not on EC2/EKS (no instance role): an IAM
  user with an access key on one of our existing buckets.

Both paths yield the same posture. The application reads four env vars
regardless:

```
TIP_MEDIA_BACKEND        = s3
TIP_MEDIA_S3_BUCKET      = <bucket name>
TIP_MEDIA_S3_REGION      = <region>
TIP_MEDIA_S3_KMS_KEY_ID  = <KMS key ARN>
```

The node's IAM credentials come from the AWS SDK default chain (IRSA
on EKS, EC2 instance role, `aws sso login` for local dev). Never put
long-lived `AWS_ACCESS_KEY_ID` in the node's environment.

---

## TL;DR: one command

```bash
cd infra/s3-media
cp terraform.tfvars.example terraform.tfvars   # 3 values: bucket_name, region, trust_mode
./setup.sh
```

Works identically for EC2 (`trust_mode=ec2`), EKS (`irsa`) and a dev
laptop (`dev`). Prints the env block for the node and the single
mode-specific wiring step. The sections below describe what it does and
the manual console/CLI path for operators who prefer that.

## A. Terraform path (recommended)

See `infra/s3-media/README.md` for the full module reference. Quick
start:

```bash
cd infra/s3-media/examples/ec2     # or examples/eks-irsa
terraform init
terraform plan -out plan.bin
terraform apply plan.bin
terraform output -json env_vars    # → wire into your deployment
```

Skip to **§ Smoke test** below to verify.

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

Pick **one** trust policy depending on how the node runs.

**EC2 instance profile** (`trust_ec2.json`):

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

**EKS IRSA** (`trust_irsa.json` — replace placeholders):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/OIDC_HOST" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "OIDC_HOST:sub": "system:serviceaccount:NAMESPACE:SERVICE_ACCOUNT",
        "OIDC_HOST:aud": "sts.amazonaws.com"
      }
    }
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

For EC2 — also create the instance profile:

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

## C. Partner node without an instance role (Lab-provided bucket)

Paths A and B give the node an **instance role**, which only exists on EC2/EKS.
A partner node running anywhere else (a Mac, a bare-metal box, another cloud)
cannot have one. For those we give the node access to the `media/` folder of
one of our existing buckets through a dedicated **IAM user** with an access
key. This is what the SS Software node runs on (user `tip-ss-node-media` on
node 1's bucket). The access key is a long-lived secret, so this path is the
exception: a partner on EC2 should run path A in their own account instead.

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

## Wiring the TIP node

### EKS pod (IRSA)

Annotate the service account:

```bash
kubectl annotate serviceaccount tip-node \
  -n tip \
  eks.amazonaws.com/role-arn=$ROLE_ARN
```

In the pod spec:

```yaml
spec:
  serviceAccountName: tip-node
  containers:
    - name: tip-node
      env:
        - { name: TIP_MEDIA_BACKEND,       value: s3 }
        - { name: TIP_MEDIA_S3_BUCKET,     value: "tip-media-prod-uswest2" }
        - { name: TIP_MEDIA_S3_REGION,     value: "us-west-2" }
        - { name: TIP_MEDIA_S3_KMS_KEY_ID, value: "<kms-key-arn>" }
```

### EC2 instance

Attach the instance profile (output `instance_profile_name` from the
Terraform module, or `$ROLE_NAME` from the CLI path). Then in your
systemd unit / docker-compose env:

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
