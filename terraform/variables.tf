variable "project" {
  description = "Project name, used in resource names and the Project tag."
  type        = string
  default     = "honeytrap"
}

variable "environment" {
  description = "Environment name (dev, research, ...)."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]{2,12}$", var.environment))
    error_message = "environment must be 2-12 lowercase letters, digits or hyphens."
  }
}

variable "region" {
  description = "AWS region. Pick one where your account's Free Tier instance types are available."
  type        = string
}

variable "availability_zone" {
  description = "AZ for the sensor; null = first available."
  type        = string
  default     = null
}

variable "instance_type" {
  description = "Sensor instance type. Free plan eligible: t3.micro, t3.small, t4g.micro, t4g.small."
  type        = string
  default     = "t3.micro"
}

variable "architecture" {
  description = "Sensor CPU architecture; must match the container image (x86_64 for t3, arm64 for t4g)."
  type        = string
  default     = "x86_64"
}

variable "sensor_name" {
  description = "Sensor identifier in events and S3 keys."
  type        = string
  default     = "honeytrap-aws-01"
}

variable "enable_telnet" {
  description = "Expose the Telnet decoy (TCP/23). Off by default: Telnet draws heavy botnet volume."
  type        = bool
  default     = false
}

variable "admin_cidr" {
  description = "Optional operator IP (/32) allowed to the real sshd on port 22022. null = no management access."
  type        = string
  default     = null
  validation {
    condition     = var.admin_cidr == null || can(regex("/32$", var.admin_cidr))
    error_message = "admin_cidr must be a single host (/32)."
  }
}

variable "enable_flow_logs" {
  description = "VPC flow logs to S3 (parquet). Small cost: vended-log delivery is billed per GB."
  type        = bool
  default     = true
}

variable "honeypot_image_path" {
  description = "Path to the gzipped Cowrie image built by scripts/package_honeypot.sh."
  type        = string
  default     = "../build/cowrie-image.tar.gz"
}

variable "lambda_zip_path" {
  description = "Path to the Lambda package built by scripts/build_lambda.sh."
  type        = string
  default     = "../build/lambda.zip"
}

variable "alert_email" {
  description = "Optional email subscribed to security alerts."
  type        = string
  default     = ""
}

variable "enable_notifications" {
  description = "Publish High/Critical alerts to SNS."
  type        = bool
  default     = true
}

variable "budget_email" {
  description = "Email for AWS Budgets notifications. Strongly recommended."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  description = "Project monthly budget in USD."
  type        = number
  default     = 5
}

variable "account_budget_usd" {
  description = "Account-wide guardrail budget in USD."
  type        = number
  default     = 10
}

variable "raw_retention_days" {
  description = "Retention for raw logs/evidence (contain attacker-typed passwords)."
  type        = number
  default     = 30
}

variable "processed_retention_days" {
  description = "Retention for processed events and alerts."
  type        = number
  default     = 90
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention."
  type        = number
  default     = 14
}

variable "force_destroy_buckets" {
  description = "Let terraform destroy delete non-empty buckets."
  type        = bool
  default     = true
}
