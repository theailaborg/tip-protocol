# Prod S3 setup for TIP media

This guide deploys the S3 backend the TIP node uses for media bytes
(`media-storage-s3.js`). Two paths are documented:

- **A.** Terraform module (`infra/s3-media/`) — recommended for
  reproducible / version-controlled infra.
- **B.** AWS Console / CLI — for one-off setups where Terraform isn't
  available.

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
