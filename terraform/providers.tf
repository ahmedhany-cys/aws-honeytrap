terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # State is local by default so a first-time user can deploy without
  # bootstrapping anything. For shared use, copy backend.tf.example to backend.tf.
}

provider "aws" {
  region = var.region
  # Credentials come from the standard AWS credential chain (profile, SSO, env).
  # Nothing is hard-coded here.

  default_tags {
    tags = {
      Project            = var.project
      Environment        = var.environment
      ManagedBy          = "terraform"
      DataClassification = "honeypot-telemetry"
      Repository         = "github.com/ahmedhany-cys/aws-honeytrap"
    }
  }
}
