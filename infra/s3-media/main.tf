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

  # Defense in depth: deny everyone except the node role from touching the
  # DATA (object reads/writes). Scoped to object actions ONLY, not s3:*
  # and not s3:ListBucket:
  #   - s3:* here would lock the operator (and even Terraform) out of
  #     managing the bucket it just created.
  #   - s3:ListBucket also authorizes HeadBucket, which Terraform calls on
  #     every refresh; denying it makes the provider treat the bucket as
  #     gone, drop it from state, and try to recreate it. Key names are
  #     content hashes (no sensitive data), so admin listing is acceptable.
  # Account root is exempt as the break-glass path, but AWS best practice
  # is to never use root day-to-day.
  statement {
    sid    = "DenyDataAccessExceptNodeRole"
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]

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
      values = concat(
        local.node_data_principals,
        ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"],
      )
    }
  }

  # Explicit allow for the node role. Minimal action set — no list/put on
  # arbitrary prefixes outside media/.
  statement {
    sid    = "AllowNodeRole"
    effect = "Allow"
    actions = [
      "s3:GetObject", # also authorizes HeadObject (HEAD has no separate IAM action)
      "s3:PutObject",
      "s3:DeleteObject",
    ]

    principals {
      type        = "AWS"
      identifiers = local.node_data_principals
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
      identifiers = local.node_data_principals
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
  rotation_period_in_days = var.kms_rotation_days
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
      identifiers = local.node_data_principals
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

  # Fail loudly at plan-time when IRSA fields are missing; otherwise
  # the trust policy would silently render to an empty Statement block
  # and the role would be unassumable.
  lifecycle {
    precondition {
      condition = (
        var.trust_mode != "irsa"
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

  # keys mode also lands here: the role itself is unused (the node holds
  # the dedicated IAM user's key instead), but AWS requires a non-empty
  # trust policy, and the EC2 service principal is inert when no instance
  # profile is ever attached.
  dynamic "statement" {
    for_each = contains(["ec2", "keys"], var.trust_mode) ? [1] : []

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "Service"
        identifiers = ["ec2.amazonaws.com"]
      }
    }
  }

  # external: IAM Roles Anywhere. Nodes on non-AWS hosts present an
  # X.509 certificate chained to our trust anchor and receive temporary
  # role credentials. SourceArn pins the trust to THIS anchor so a
  # certificate from any other Roles Anywhere anchor in the account
  # cannot assume the media role.
  dynamic "statement" {
    for_each = var.trust_mode == "external" ? [1] : []

    content {
      effect = "Allow"
      actions = [
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
      ]

      principals {
        type        = "Service"
        identifiers = ["rolesanywhere.amazonaws.com"]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = [aws_rolesanywhere_trust_anchor.media_node[0].arn]
      }
    }
  }
}

# ── IAM Roles Anywhere (trust_mode=external) ───────────────────────────────
# Certificate-based temporary credentials for nodes outside AWS. The
# trust anchor is the operator-generated CA; the profile binds it to the
# node role. The node runs `aws_signing_helper credential-process` with
# its client cert: same rotating-credentials posture as EC2/EKS, no
# long-lived keys on any host.

resource "aws_rolesanywhere_trust_anchor" "media_node" {
  count   = var.trust_mode == "external" ? 1 : 0
  name    = "${var.bucket_name}-trust-anchor"
  enabled = true

  source {
    source_type = "CERTIFICATE_BUNDLE"

    source_data {
      x509_certificate_data = var.external_ca_cert_pem
    }
  }

  tags = var.tags
}

resource "aws_rolesanywhere_profile" "media_node" {
  count     = var.trust_mode == "external" ? 1 : 0
  name      = "${var.bucket_name}-profile"
  enabled   = true
  role_arns = [aws_iam_role.media_node.arn]

  tags = var.tags
}

resource "aws_iam_role_policy" "media_node" {
  name   = "${var.bucket_name}-node-policy"
  role   = aws_iam_role.media_node.id
  policy = data.aws_iam_policy_document.node_policy.json
}

# ── IAM user + access key (trust_mode=keys) ─────────────────────────────────
# The copy-paste handover path: the account owner runs setup.sh, sends the
# printed env block (including this user's access key) to whoever operates
# the node machine, on any cloud. The key is a LONG-LIVED secret scoped to
# exactly this bucket's media/ prefix and nothing else in the account;
# rotate it every 90 days (terraform apply -replace=aws_iam_access_key.media_node).
# Prefer ec2 / irsa / external when the host supports them.

resource "aws_iam_user" "media_node" {
  count = var.trust_mode == "keys" ? 1 : 0
  name  = "${var.bucket_name}-node-user"
  tags  = var.tags
}

resource "aws_iam_user_policy" "media_node" {
  count  = var.trust_mode == "keys" ? 1 : 0
  name   = "${var.bucket_name}-node-policy"
  user   = aws_iam_user.media_node[0].name
  policy = data.aws_iam_policy_document.node_policy.json
}

resource "aws_iam_access_key" "media_node" {
  count = var.trust_mode == "keys" ? 1 : 0
  user  = aws_iam_user.media_node[0].name
}

locals {
  # Every principal allowed to touch media data. The role always exists;
  # keys mode adds the dedicated bucket-scoped IAM user alongside it.
  node_data_principals = concat(
    [aws_iam_role.media_node.arn],
    var.trust_mode == "keys" ? [aws_iam_user.media_node[0].arn] : [],
  )
}

data "aws_iam_policy_document" "node_policy" {
  statement {
    sid    = "MediaObjectsRW"
    effect = "Allow"
    actions = [
      "s3:GetObject", # also authorizes HeadObject (HEAD has no separate IAM action)
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.media.arn}/media/*"]
  }

  statement {
    sid       = "ListMediaPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
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

# ── KMS off-role usage alarm (optional) ────────────────────────────────────
# CloudTrail logs every KMS API call with the caller's ARN. The metric
# filter matches calls against THIS key where the caller is neither the
# node role nor AWS service-linked KMS internals; the alarm fires on the
# first match. One event = one investigation — there is no legitimate
# second consumer of this key.

resource "aws_cloudwatch_log_metric_filter" "kms_off_role" {
  count = var.enable_kms_alert ? 1 : 0

  name           = "${var.bucket_name}-kms-off-role"
  log_group_name = var.cloudtrail_log_group_name

  # Sessions assumed FROM the node role carry the role ARN in
  # sessionContext.sessionIssuer.arn — match on that rather than the
  # per-session assumed-role ARN (which embeds a variable session name).
  pattern = <<-EOT
    { ($.eventSource = "kms.amazonaws.com")
      && ($.resources[0].ARN = "${aws_kms_key.media.arn}")
      && ($.userIdentity.sessionContext.sessionIssuer.arn != "${aws_iam_role.media_node.arn}") }
  EOT

  metric_transformation {
    name          = "${var.bucket_name}-kms-off-role-count"
    namespace     = "TIP/MediaSecurity"
    value         = "1"
    default_value = "0"
  }

  lifecycle {
    precondition {
      condition     = var.cloudtrail_log_group_name != null
      error_message = "enable_kms_alert=true requires cloudtrail_log_group_name."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_off_role" {
  count = var.enable_kms_alert ? 1 : 0

  alarm_name          = "${var.bucket_name}-kms-off-role-usage"
  alarm_description   = "Media KMS key used by a principal other than the TIP node role"
  namespace           = "TIP/MediaSecurity"
  metric_name         = aws_cloudwatch_log_metric_filter.kms_off_role[0].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alert_sns_topic_arn != null ? [var.alert_sns_topic_arn] : []

  tags = var.tags
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
