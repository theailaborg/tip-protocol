# © 2026 The AI Lab Intelligence Unobscured, Inc.
# License: TIPCL-1.0
#
# Example: TIP media bucket consumed by a TIP node running on EC2 (or
# docker-compose on EC2). The node assumes the role via the EC2 instance
# profile this module creates.
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

module "tip_media" {
  source = "../.."

  bucket_name = "tip-media-prod-example"
  region      = "us-west-2"

  trust_mode = "ec2"

  # Optional VPC endpoint — saves NAT-gateway egress charges on S3 traffic.
  # Comment out / set false if you don't need it.
  # create_vpc_endpoint = true
  # vpc_id              = "vpc-XXXXXXXX"
  # route_table_ids     = ["rtb-AAAAAAAA", "rtb-BBBBBBBB"]

  tags = {
    Environment = "prod"
    Component   = "tip-media"
  }
}

# ── Wire the instance profile to your EC2 launch template / autoscaling
#    group. ───────────────────────────────────────────────────────────────

output "instance_profile_name" {
  description = "Attach this instance profile to the TIP-node EC2 instances."
  value       = module.tip_media.node_instance_profile_name
}

output "env_vars" {
  description = "Set these on the TIP node process (systemd unit / docker-compose env)."
  value       = module.tip_media.tip_node_env_vars
}

# Example wiring with an EC2 instance:
#
#   resource "aws_instance" "tip_node" {
#     ami                  = "ami-XXXXXXXX"
#     instance_type        = "m6i.large"
#     iam_instance_profile = module.tip_media.node_instance_profile_name
#     # ... your usual user_data, networking, etc.
#   }
#
# The AWS SDK in the TIP node picks up credentials from IMDSv2 — no env
# keys required. The role is least-privilege (only the media bucket +
# KMS key).
