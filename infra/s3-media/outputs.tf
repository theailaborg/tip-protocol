# © 2026 The AI Lab Intelligence Unobscured, Inc.
# License: TIPCL-1.0

output "bucket_name" {
  description = "S3 bucket name for the TIP media backend."
  value       = aws_s3_bucket.media.id
}

output "bucket_arn" {
  description = "S3 bucket ARN."
  value       = aws_s3_bucket.media.arn
}

output "region" {
  description = "AWS region (echoed from input)."
  value       = var.region
}

output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key encrypting media objects."
  value       = aws_kms_key.media.arn
}

output "kms_key_id" {
  description = "KMS key ID."
  value       = aws_kms_key.media.key_id
}

output "kms_key_alias" {
  description = "KMS key alias (e.g. alias/tip-media-<bucket>)."
  value       = aws_kms_alias.media.name
}

output "node_role_arn" {
  description = <<-EOT
    IAM role ARN the TIP node assumes. For EKS attach this to a service
    account via the eks.amazonaws.com/role-arn annotation. For EC2,
    attach the matching instance profile.
  EOT
  value       = aws_iam_role.media_node.arn
}

output "node_instance_profile_name" {
  description = "Instance profile name (only set when trust_mode=ec2)."
  value       = try(aws_iam_instance_profile.media_node[0].name, null)
}

output "vpc_endpoint_id" {
  description = "Gateway VPC endpoint ID (only set when create_vpc_endpoint=true)."
  value       = try(aws_vpc_endpoint.s3[0].id, null)
}

# Convenience: env vars the TIP node consumes. Pipe these straight into
# your deployment manifest / Helm values / docker-compose env section.
output "tip_node_env_vars" {
  description = "Environment variables to set on the TIP node process."
  value = {
    TIP_MEDIA_BACKEND       = "s3"
    TIP_MEDIA_S3_BUCKET     = aws_s3_bucket.media.id
    TIP_MEDIA_S3_REGION     = var.region
    TIP_MEDIA_S3_KMS_KEY_ID = aws_kms_key.media.arn
  }
}
