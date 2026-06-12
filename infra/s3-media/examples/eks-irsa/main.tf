# © 2026 The AI Lab Intelligence Unobscured, Inc.
# License: TIPCL-1.0
#
# Example: TIP media bucket consumed by a TIP node running as an EKS pod
# via IRSA (IAM Roles for Service Accounts).
#
# Prerequisites the operator must have already provisioned:
#   - An EKS cluster with an OIDC provider configured.
#   - A Kubernetes namespace for the TIP node.
#   - A service account in that namespace; this module attaches the IAM
#     role to it via the `eks.amazonaws.com/role-arn` annotation
#     (you annotate the SA manually; see usage notes at the bottom).
#
# Run:
#   terraform init
#   terraform apply

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# ── Inputs you'll typically pull from data sources or outputs of the
#    cluster module. Inlined here for illustration. ────────────────────────

variable "cluster_oidc_provider_arn" {
  description = "ARN of the cluster's OIDC provider, e.g. from terraform-aws-modules/eks."
  type        = string
}

variable "cluster_oidc_issuer_host" {
  description = "Hostname of the OIDC issuer (no scheme), e.g. oidc.eks.us-west-2.amazonaws.com/id/XXXXXX."
  type        = string
}

variable "vpc_id" {
  type    = string
  default = null
}

variable "private_route_table_ids" {
  type    = list(string)
  default = []
}

# ── Module call ────────────────────────────────────────────────────────────

module "tip_media" {
  source = "../.."

  bucket_name = "tip-media-prod-example"
  region      = "us-west-2"

  trust_mode          = "irsa"
  oidc_provider_arn   = var.cluster_oidc_provider_arn
  oidc_issuer_host    = var.cluster_oidc_issuer_host
  k8s_namespace       = "tip"
  k8s_service_account = "tip-node"

  # Recommended: keep node↔S3 traffic on the AWS backbone. Set vpc_id
  # and route_table_ids to your private RTBs.
  create_vpc_endpoint = true
  vpc_id              = var.vpc_id
  route_table_ids     = var.private_route_table_ids

  tags = {
    Environment = "prod"
    Component   = "tip-media"
  }
}

# ── Outputs you wire into the deployment ──────────────────────────────────

output "node_role_arn" {
  description = "Annotate the service account 'tip/tip-node' with eks.amazonaws.com/role-arn = this value."
  value       = module.tip_media.node_role_arn
}

output "env_vars" {
  description = "Set these on the TIP node container."
  value       = module.tip_media.tip_node_env_vars
}

# After `terraform apply`, annotate the service account once:
#
#   kubectl annotate serviceaccount tip-node \
#     -n tip \
#     eks.amazonaws.com/role-arn=$(terraform output -raw node_role_arn)
#
# Then deploy your TIP node pod with that SA. The AWS SDK in the node
# picks up credentials from the projected service-account token
# automatically — no AWS_ACCESS_KEY_ID required.
