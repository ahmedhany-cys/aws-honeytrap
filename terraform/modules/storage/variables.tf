variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "account_id" {
  description = "AWS account ID, used to make bucket names globally unique."
  type        = string
}

variable "force_destroy" {
  description = "Allow terraform destroy to delete non-empty buckets (lab teardown)."
  type        = bool
  default     = true
}

variable "raw_retention_days" {
  description = "Days to keep raw Cowrie logs and evidence (contain clear-text attacker passwords)."
  type        = number
  default     = 30
}

variable "processed_retention_days" {
  description = "Days to keep processed events, alerts and enrichment."
  type        = number
  default     = 90
}

variable "flow_log_retention_days" {
  description = "Days to keep VPC flow logs."
  type        = number
  default     = 14
}
