variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "vpc_id" {
  description = "Honeypot VPC."
  type        = string
}

variable "subnet_id" {
  description = "Honeypot subnet."
  type        = string
}

variable "s3_prefix_list_id" {
  description = "S3 managed prefix list - the only egress destination."
  type        = string
}

variable "instance_type" {
  description = "Free Tier eligible instance type (t3.micro / t4g.micro on the Free plan)."
  type        = string
  default     = "t3.micro"
}

variable "architecture" {
  description = "x86_64 or arm64. Must match the architecture the container image was built for."
  type        = string
  default     = "x86_64"
  validation {
    condition     = contains(["x86_64", "arm64"], var.architecture)
    error_message = "architecture must be x86_64 or arm64."
  }
}

variable "root_volume_gb" {
  description = "Root EBS volume size (Free Tier: 30 GB total)."
  type        = number
  default     = 8
}

variable "enable_telnet" {
  description = "Expose the Telnet decoy on TCP/23. Telnet attracts very high botnet volume."
  type        = bool
  default     = false
}

variable "admin_cidr" {
  description = "Optional operator /32 for the real sshd. null disables sshd entirely."
  type        = string
  default     = null
}

variable "admin_ssh_port" {
  description = "Port for the operator sshd."
  type        = number
  default     = 22022
}

variable "telemetry_bucket" {
  description = "Telemetry bucket name."
  type        = string
}

variable "artifacts_bucket" {
  description = "Artifacts bucket name."
  type        = string
}

variable "sensor_name" {
  description = "Sensor identifier written into every event and S3 key."
  type        = string
}

variable "honeypot_image_path" {
  description = "Local path of the gzipped Cowrie container image (scripts/package_honeypot.sh)."
  type        = string
}

variable "ship_interval_minutes" {
  description = "How often the shipper uploads new telemetry."
  type        = number
  default     = 5
}
