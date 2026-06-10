# © 2026 The AI Lab Intelligence Unobscured, Inc.
# License: TIPCL-1.0

# ── Bucket identity ────────────────────────────────────────────────────────

variable "bucket_name" {
  description = "Globally-unique S3 bucket name for TIP media bytes."
  type        = string
}

variable "region" {
  description = "AWS region (informational — used to populate env-var output)."
  type        = string
  default     = "us-west-2"
}

variable "tags" {
  description = "Tags applied to every resource the module creates."
  type        = map(string)
  default     = {}
}

# ── Trust model for the node role ──────────────────────────────────────────

variable "trust_mode" {
  description = <<-EOT
    How the node's IAM role is assumed:
      - "irsa" — pod-level role via the EKS OIDC provider (preferred for EKS).
      - "ec2"  — instance profile (for EC2-hosted nodes / docker-compose).
    Both produce a role with the same S3+KMS permissions; only the trust
    policy differs.
  EOT
  type        = string
  default     = "ec2"

  validation {
    condition     = contains(["irsa", "ec2"], var.trust_mode)
    error_message = "trust_mode must be \"irsa\" or \"ec2\"."
  }
}

variable "oidc_provider_arn" {
  description = "EKS cluster's OIDC provider ARN. Required when trust_mode=irsa."
  type        = string
  default     = null
}

variable "oidc_issuer_host" {
  description = <<-EOT
    Host portion of the OIDC issuer URL (e.g. "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE").
    Required when trust_mode=irsa. Used in the trust policy condition keys.
  EOT
  type        = string
  default     = null
}

variable "k8s_namespace" {
  description = "Kubernetes namespace running the TIP node pod. Required when trust_mode=irsa."
  type        = string
  default     = null
}

variable "k8s_service_account" {
  description = "Kubernetes service account name for the TIP node pod. Required when trust_mode=irsa."
  type        = string
  default     = null
}

# ── VPC endpoint (optional) ────────────────────────────────────────────────

variable "create_vpc_endpoint" {
  description = <<-EOT
    Create a gateway VPC endpoint for S3 so node↔bucket traffic stays on the
    AWS backbone. Required for EKS pods without internet egress; nice-to-have
    for everyone else (eliminates NAT-gateway cost on S3 reads).
  EOT
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC where the gateway endpoint is attached. Required when create_vpc_endpoint=true."
  type        = string
  default     = null
}

variable "route_table_ids" {
  description = "Route tables the gateway endpoint is associated with. Required when create_vpc_endpoint=true."
  type        = list(string)
  default     = []
}

# ── Retention backstop ─────────────────────────────────────────────────────

variable "lifecycle_backstop_days" {
  description = <<-EOT
    S3 lifecycle expiration as a backstop for the app-side retention sweep.
    The application sweeps deletes media at base 21d (never disputed) +
    7d cool-down (post adjudication / appeal). This is just disaster
    insurance — should the sweep be disabled or broken, S3 still reaps
    abandoned bytes. Set generous (90d default) so it never preempts the
    app-side window.
  EOT
  type        = number
  default     = 90
}

# ── Access logs (opt-in) ───────────────────────────────────────────────────

variable "enable_access_logs" {
  description = "Enable S3 server access logging (cheap audit trail; replaces the in-app access log we deliberately skipped)."
  type        = bool
  default     = false
}

variable "access_logs_bucket" {
  description = "Pre-existing bucket to write access logs to. Required when enable_access_logs=true."
  type        = string
  default     = null
}

variable "access_logs_prefix" {
  description = "Object-key prefix inside the access-logs bucket."
  type        = string
  default     = "tip-media/"
}

# ── KMS ────────────────────────────────────────────────────────────────────

variable "kms_deletion_window_days" {
  description = "Deletion window for the customer-managed KMS key (7-30)."
  type        = number
  default     = 30
}

variable "kms_rotation_days" {
  description = "Automatic rotation period for the media KMS key (90-2560)."
  type        = number
  default     = 90
}

# ── KMS anomaly alarm (opt-in) ─────────────────────────────────────────────
# Fires when the media KMS key is used by ANY principal other than the
# node role. Catches stolen-credential / misconfigured-grant scenarios.
# Requires an account-level CloudTrail that delivers management events to
# a CloudWatch Logs group (standard org posture; not created here).

variable "enable_kms_alert" {
  description = "Create the CloudTrail metric filter + alarm for off-role KMS usage."
  type        = bool
  default     = false
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch Logs group receiving CloudTrail management events. Required when enable_kms_alert=true."
  type        = string
  default     = null
}

variable "alert_sns_topic_arn" {
  description = "SNS topic notified when the KMS alarm fires. Optional — alarm still records state without it."
  type        = string
  default     = null
}
