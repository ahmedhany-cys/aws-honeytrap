variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR for the dedicated honeypot VPC. Must not overlap any network you might ever peer (it never will be)."
  type        = string
  default     = "10.42.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR for the single honeypot subnet."
  type        = string
  default     = "10.42.1.0/24"
}

variable "availability_zone" {
  description = "AZ for the honeypot subnet."
  type        = string
}

variable "enable_telnet" {
  description = "Open TCP/23 in the NACL."
  type        = bool
  default     = false
}

variable "admin_cidr" {
  description = "Optional /32 allowed to reach the real sshd on admin_ssh_port. null = no admin path at all."
  type        = string
  default     = null
}

variable "admin_ssh_port" {
  description = "Port of the real (management) sshd when admin_cidr is set."
  type        = number
  default     = 22022
}

variable "allowed_bucket_arns" {
  description = "Bucket ARNs the S3 gateway endpoint policy allows."
  type        = list(string)
}

variable "enable_flow_logs" {
  description = "Deliver VPC flow logs (parquet) to flow_logs_bucket_arn. A bool, so count is known at plan time."
  type        = bool
  default     = true
}

variable "flow_logs_bucket_arn" {
  description = "Bucket ARN for VPC flow logs."
  type        = string
  default     = null
}
