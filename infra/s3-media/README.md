# infra/s3-media — Terraform module for the TIP media S3 backend

Storage is **per-node**: each operator provisions, pays for, and serves
their own bucket. Bytes live only on the node that received the upload;
peers reach them through the reviewer-access route's 307 redirect to the
node's on-chain `api_endpoint`. Recommended bucket naming:
`tip-node-{node_id_short}-media-{region}`.

Provisions the AWS infrastructure required by `media-storage-s3.js`:

- **S3 bucket** with Block Public Access, SSE-KMS encryption, HTTPS-only,
  deny-by-default bucket policy, lifecycle backstop.
- **Customer-managed KMS key** with rotation enabled and key policy
  scoped to the node role only.
- **IAM role** for the TIP node with minimal grants (`s3:GetObject`,
  `s3:PutObject`, `s3:HeadObject`, `s3:DeleteObject`, `s3:ListBucket`,
  `kms:Encrypt/Decrypt/GenerateDataKey/DescribeKey`).
- **Trust policy** toggled between IRSA (EKS) and EC2 instance profile.
- **Optional** S3 gateway VPC endpoint and bucket access logs.

The module's outputs include `tip_node_env_vars` — the four env vars
the TIP node consumes (`TIP_MEDIA_BACKEND`, `TIP_MEDIA_S3_BUCKET`,
`TIP_MEDIA_S3_REGION`, `TIP_MEDIA_S3_KMS_KEY_ID`).

## Usage

```hcl
module "tip_media" {
  source = "github.com/theailaborg/tip-protocol//infra/s3-media?ref=v2.x.x"

  bucket_name = "tip-media-prod-uswest2"
  region      = "us-west-2"

  trust_mode = "ec2"        # or "irsa" for EKS pods

  tags = {
    Environment = "prod"
    Component   = "tip-media"
  }
}

output "tip_node_env" {
  value = module.tip_media.tip_node_env_vars
}
```

See `examples/` for complete IRSA and EC2 wirings.

## Inputs

| Name | Type | Default | Purpose |
|---|---|---|---|
| `bucket_name` | string | — | Globally-unique S3 bucket name. **Required.** |
| `region` | string | `us-west-2` | Region (echoed into outputs). |
| `tags` | map(string) | `{}` | Tags on every resource. |
| `trust_mode` | string | `ec2` | `ec2` or `irsa`. |
| `oidc_provider_arn` | string | `null` | EKS OIDC provider ARN (required when `trust_mode=irsa`). |
| `oidc_issuer_host` | string | `null` | OIDC issuer hostname (required when `irsa`). |
| `k8s_namespace` | string | `null` | Namespace of the TIP node pod (required when `irsa`). |
| `k8s_service_account` | string | `null` | Service account name (required when `irsa`). |
| `create_vpc_endpoint` | bool | `false` | Provision a gateway endpoint for S3. |
| `vpc_id` | string | `null` | VPC for the endpoint (required when `create_vpc_endpoint=true`). |
| `route_table_ids` | list(string) | `[]` | Route tables to attach the endpoint to. |
| `lifecycle_backstop_days` | number | `90` | Backstop expiration on `media/` prefix. |
| `enable_access_logs` | bool | `false` | Turn on S3 server access logs. |
| `access_logs_bucket` | string | `null` | Pre-existing bucket for access logs. |
| `access_logs_prefix` | string | `tip-media/` | Prefix inside that bucket. |
| `kms_deletion_window_days` | number | `30` | KMS key deletion window (7–30). |

## Outputs

| Name | Purpose |
|---|---|
| `bucket_name` / `bucket_arn` | Identify the bucket. |
| `region` | Echo. |
| `kms_key_arn` / `kms_key_id` / `kms_key_alias` | Identify the SSE-KMS key. |
| `node_role_arn` | IAM role the TIP node assumes. |
| `node_instance_profile_name` | Only set when `trust_mode=ec2`. |
| `vpc_endpoint_id` | Only set when `create_vpc_endpoint=true`. |
| `tip_node_env_vars` | Map of the four env vars to set on the node. |

## Security posture (what the module enforces)

| Control | Layer |
|---|---|
| No public bucket access | `aws_s3_bucket_public_access_block` (cannot be overridden) |
| ACLs disabled (bucket-owner-enforced) | `aws_s3_bucket_ownership_controls` |
| Default encryption | `aws_s3_bucket_server_side_encryption_configuration` (SSE-KMS) |
| HTTPS only | Bucket policy `DenyInsecureTransport` (`aws:SecureTransport=false`) |
| Deny-by-default | Bucket policy `DenyEveryoneExceptNodeRole` (PrincipalArn check) |
| KMS key reuse limited to S3 | Key policy `kms:ViaService` condition |
| Annual key rotation | `aws_kms_key.enable_key_rotation = true` |
| Versioning off | Content-addressed; versioning would only inflate cost |
| Stuck multipart uploads aborted | Lifecycle rule (7d) |
| App-side retention backstop | Lifecycle rule (90d default; see `M6` in `node/src/services/media-retention.js`) |

## What the module does NOT do

- **Create the EKS cluster / OIDC provider.** Bring your own; pass the
  provider ARN in.
- **Create the VPC / subnets / route tables.** Bring your own; pass the
  VPC ID and RTBs in.
- **Annotate Kubernetes service accounts.** Run the `kubectl annotate`
  command after `apply`. See the IRSA example.
- **Bootstrap an access-logs bucket.** Create one separately and pass
  it in via `access_logs_bucket`.

## Operator workflow

1. `terraform init`
2. `terraform plan -out plan.bin` and review.
3. `terraform apply plan.bin`.
4. Capture outputs: `terraform output -json tip_node_env_vars`.
5. Wire those env vars into your node deployment (Helm values /
   systemd unit / docker-compose env).
6. For EKS only: annotate the pod's service account with the
   `eks.amazonaws.com/role-arn` output.
7. Verify end-to-end — see `docs/PROD_S3_SETUP.md` for the smoke test.

## Relationship to the app

This module owns the **backend**. The application's behaviour against
it is owned in code:

- Object writes / reads / deletes:
  `node/src/services/media-storage-s3.js`
- Pre-signed URL minting for reviewers (TTL = 300s):
  `node/src/services/media-storage-s3.js`
- Retention sweep (`21d` base, `7d` after adjudication / appeal):
  `node/src/services/media-retention.js`
- The bucket-policy `media/*` resource scope MUST match the object-key
  layout in `media-storage-s3.js._objectKey()` (currently
  `media/{shard}/{rest}.bin`). If you change one, change both.
