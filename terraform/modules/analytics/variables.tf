variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "telemetry_bucket" {
  description = "Telemetry bucket name."
  type        = string
}

variable "bytes_scanned_cutoff" {
  description = "Hard cap on bytes scanned per Athena query (Athena bills per TB scanned; 10 MB minimum per query)."
  type        = number
  default     = 104857600
}
