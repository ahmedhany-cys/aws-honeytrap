variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "project_tag" {
  description = "Value of the Project cost-allocation tag (activate it in Billing to make the project budget accurate)."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Project budget. Alerts at 25% and 80% actual, 100% forecast."
  type        = number
  default     = 5
}

variable "account_budget_usd" {
  description = "Account-wide guardrail budget."
  type        = number
  default     = 10
}

variable "budget_email" {
  description = "Email for budget alerts. Empty = budgets created without notifications."
  type        = string
  default     = ""
}

variable "alarm_topic_arn" {
  description = "SNS topic for operational alarms."
  type        = string
}

variable "function_names" {
  description = "Map of Lambda key => function name."
  type        = map(string)
}

variable "dlq_name" {
  description = "Pipeline DLQ name."
  type        = string
}

variable "instance_id" {
  description = "Honeypot instance ID."
  type        = string
}
