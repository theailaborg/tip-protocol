# © 2026 The AI Lab Intelligence Unobscured, Inc.
# License: TIPCL-1.0

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}
