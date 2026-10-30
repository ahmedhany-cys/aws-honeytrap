variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "telemetry_bucket" {
  description = "Telemetry bucket name."
  type        = string
}

variable "lambda_zip_path" {
  description = "Path of the Lambda deployment package built by scripts/build_lambda.sh."
  type        = string
}

variable "alert_email" {
  description = "Optional email subscribed to the alert topic (requires confirming the AWS email)."
  type        = string
  default     = ""
}

variable "enable_notifications" {
  description = "Publish alerts at or above the configured severity to SNS."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambdas."
  type        = number
  default     = 14
}

variable "enrichment_lookup_limit" {
  description = "Max new enrichment lookups per invocation (protects free API quotas)."
  type        = number
  default     = 25
}
