# © 2026 The AI Lab Intelligence Unobscured, Inc.
# License: TIPCL-1.0
#
# TIP media storage — prod posture for the S3 backend used by
# node/src/services/media-storage-s3.js.
#
# Security model:
#   - Bucket has Block Public Access enabled at the bucket level.
#   - Bucket policy denies every action unless the principal is the node
#     IAM role this module creates. Anonymous / cross-account access
#     fails at the bucket-policy layer even before IAM evaluation.
#   - Default encryption is SSE-KMS with a customer-managed key. KMS key
#     policy grants encrypt/decrypt only to the node role.
#   - HTTPS is required (aws:SecureTransport condition).
#   - Optional VPC gateway endpoint keeps traffic on the AWS backbone.
#
# Lifecycle:
#   - The TIP node runs the M6 retention sweep (delete after 21d base /
#     7d adjudication / 7d appeal). The S3 lifecycle rule here is a
#     90-day backstop — any object older than that is deleted regardless,
#     covering the case where the sweep is offline.
#   - Incomplete multi-part uploads >7 days are aborted automatically.

data "aws_caller_identity" "current" {}

# ── S3 bucket ──────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "media" {
  bucket = var.bucket_name
  tags   = merge(var.tags, { Name = var.bucket_name })
}

# Hard floor: no public access at the bucket level. Even an explicit
# allow in the bucket policy can't override these.
resource "aws_s3_bucket_public_access_block" "media" {
  bucket = aws_s3_bucket.media.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Ownership controls: bucket owner enforced (ACLs disabled). Eliminates
# the "object uploaded by another principal can't be read by the owner"
# foot-gun and removes the ACL surface entirely.
resource "aws_s3_bucket_ownership_controls" "media" {
  bucket = aws_s3_bucket.media.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Default encryption: SSE-KMS with the customer-managed key created
# below. bucket_key_enabled cuts KMS request volume / cost roughly 99%.
resource "aws_s3_bucket_server_side_encryption_configuration" "media" {
  bucket = aws_s3_bucket.media.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.media.arn
    }
    bucket_key_enabled = true
  }
}

# Versioning Suspended — media is content-addressed (media_id =
# shake256(bytes)), so identical uploads dedup to one object and there's
# no "edit" semantic. Versioning would only inflate storage cost
# without recovering anything the protocol can't reproduce from the
# original signer. (The AWS API doesn't accept "Disabled" for the
# `Status` field — "Suspended" is the canonical value for "off" on a
# new bucket and also handles the case where versioning was once on.)
resource "aws_s3_bucket_versioning" "media" {
  bucket = aws_s3_bucket.media.id

  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "media" {
  bucket = aws_s3_bucket.media.id

  rule {
    id     = "abort-stuck-multipart"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "media-backstop-deletion"
    status = "Enabled"

    filter {
      prefix = "media/"
    }

    expiration {
      days = var.lifecycle_backstop_days
    }
  }
}

resource "aws_s3_bucket_logging" "media" {
  count = var.enable_access_logs ? 1 : 0

  bucket        = aws_s3_bucket.media.id
  target_bucket = var.access_logs_bucket
  target_prefix = var.access_logs_prefix

  lifecycle {
    precondition {
      condition     = var.access_logs_bucket != null
      error_message = "enable_access_logs=true requires access_logs_bucket to be set."
    }
  }
}

# ── Bucket policy ──────────────────────────────────────────────────────────

resource "aws_s3_bucket_policy" "media" {
  bucket = aws_s3_bucket.media.id
  policy = data.aws_iam_policy_document.bucket.json

  # Make the policy land AFTER public-access-block so we never have a
  # window where a permissive policy without PAB could be public.
  depends_on = [aws_s3_bucket_public_access_block.media]
}

data "aws_iam_policy_document" "bucket" {
  # HTTPS-only. Catches anyone who misconfigures their client.
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.media.arn,
      "${aws_s3_bucket.media.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Defense in depth: deny every principal except the node role and the
  # account root. PrincipalArn check covers all paths (IAM users, roles,
  # federated identities) without enumerating each.
  statement {
    sid     = "DenyEveryoneExceptNodeRole"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.media.arn,
      "${aws_s3_bucket.media.arn}/*",
    ]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "aws:PrincipalArn"
      values = [
        aws_iam_role.media_node.arn,
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      ]
    }
  }

  # Explicit allow for the node role. Minimal action set — no list/put on
  # arbitrary prefixes outside media/.
  statement {
    sid    = "AllowNodeRole"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:HeadObject",
      "s3:DeleteObject",
    ]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.media_node.arn]
    }

    resources = ["${aws_s3_bucket.media.arn}/media/*"]
  }

  # ListBucket scoped to the media/ prefix so the retention sweep can
  # paginate ListObjectsV2 without seeing access-log keys (if logs are
  # in the same bucket — they shouldn't be, but defense in depth).
  statement {
    sid     = "AllowNodeRoleListMediaPrefix"
    effect  = "Allow"
    actions = ["s3:ListBucket"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.media_node.arn]
    }

    resources = [aws_s3_bucket.media.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["media/*", "media/"]
    }
  }
}

# ── KMS key ────────────────────────────────────────────────────────────────

resource "aws_kms_key" "media" {
  description             = "TIP media SSE-KMS for s3://${var.bucket_name}"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "media" {
  name          = "alias/tip-media-${var.bucket_name}"
  target_key_id = aws_kms_key.media.key_id
}

data "aws_iam_policy_document" "kms" {
  # Account root keeps key admin — required to ever rotate or delete.
  statement {
    sid     = "EnableRootPermissions"
    effect  = "Allow"
    actions = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    resources = ["*"]
  }

  # Node role can use the key for SSE-KMS PUT/GET. No grant for key
  # admin / rotation / deletion.
  statement {
    sid    = "AllowNodeRoleUseForEncryption"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.media_node.arn]
    }

    resources = ["*"]

    # Scope to S3 service so the role can only use this key for bucket
    # operations, not arbitrary encrypt-anything-with-this-key.
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

# ── IAM role for the TIP node ──────────────────────────────────────────────

resource "aws_iam_role" "media_node" {
  name               = "${var.bucket_name}-node-role"
  assume_role_policy = data.aws_iam_policy_document.trust.json
  tags               = var.tags

  # Fail loudly at plan-time when IRSA fields are missing — otherwise
  # the trust policy would silently render to an empty Statement block
  # and the role would be unassumable.
  lifecycle {
    precondition {
      condition = (
        var.trust_mode == "ec2"
        || (
          var.oidc_provider_arn != null
          && var.oidc_issuer_host != null
          && var.k8s_namespace != null
          && var.k8s_service_account != null
        )
      )
      error_message = "trust_mode=irsa requires oidc_provider_arn, oidc_issuer_host, k8s_namespace, and k8s_service_account."
    }
  }
}

# Trust policy is the only thing that differs between IRSA and EC2.
# Permissions attached to the role are identical.
data "aws_iam_policy_document" "trust" {
  dynamic "statement" {
    for_each = var.trust_mode == "irsa" ? [1] : []

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]

      principals {
        type        = "Federated"
        identifiers = [var.oidc_provider_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "${var.oidc_issuer_host}:sub"
        values   = ["system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"]
      }

      condition {
        test     = "StringEquals"
        variable = "${var.oidc_issuer_host}:aud"
        values   = ["sts.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.trust_mode == "ec2" ? [1] : []

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "Service"
        identifiers = ["ec2.amazonaws.com"]
      }
    }
  }
}

resource "aws_iam_role_policy" "media_node" {
  name   = "${var.bucket_name}-node-policy"
  role   = aws_iam_role.media_node.id
  policy = data.aws_iam_policy_document.node_policy.json
}

data "aws_iam_policy_document" "node_policy" {
  statement {
    sid    = "MediaObjectsRW"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:HeadObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.media.arn}/media/*"]
  }

  statement {
    sid    = "ListMediaPrefix"
    effect = "Allow"
    actions = ["s3:ListBucket"]
    resources = [aws_s3_bucket.media.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["media/*", "media/"]
    }
  }

  statement {
    sid    = "UseMediaKmsKey"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.media.arn]
  }
}

# Instance profile only needed for trust_mode=ec2. EKS pods reach the
# role via IRSA + the service account; no instance profile involved.
resource "aws_iam_instance_profile" "media_node" {
  count = var.trust_mode == "ec2" ? 1 : 0

  name = aws_iam_role.media_node.name
  role = aws_iam_role.media_node.name
}

# ── VPC endpoint (optional) ────────────────────────────────────────────────

resource "aws_vpc_endpoint" "s3" {
  count = var.create_vpc_endpoint ? 1 : 0

  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.route_table_ids

  # Endpoint policy further restricts which principals + resources can
  # traverse it. Even if an attacker controlled an EC2 in the VPC, they
  # couldn't reach OTHER S3 buckets via this endpoint.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.media_node.arn
      }
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:HeadObject",
        "s3:DeleteObject",
        "s3:ListBucket",
      ]
      Resource = [
        aws_s3_bucket.media.arn,
        "${aws_s3_bucket.media.arn}/*",
      ]
    }]
  })

  tags = var.tags
}
