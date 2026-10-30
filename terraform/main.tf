# AWS HoneyTrap - root composition.
#
#   network    dedicated VPC, public subnet, NACL, S3 gateway endpoint, flow logs
#   storage    telemetry + artifacts buckets (encrypted, private, lifecycle-managed)
#   honeypot   Cowrie sensor on EC2 with S3-only egress and a write-only IAM role
#   pipeline   EventBridge -> Lambda processor/correlator -> S3 alerts -> SNS
#   analytics  Glue catalog + Athena workgroup with a scan cap
#   monitoring budgets, Lambda/DLQ/EC2/no-telemetry alarms

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only used as a default; set var.availability_zone to pin a specific AZ.
  state = "available"
}

locals {
  name              = "${var.project}-${var.environment}"
  availability_zone = coalesce(var.availability_zone, data.aws_availability_zones.available.names[0])
}

module "storage" {
  source                   = "./modules/storage"
  name                     = local.name
  account_id               = data.aws_caller_identity.current.account_id
  force_destroy            = var.force_destroy_buckets
  raw_retention_days       = var.raw_retention_days
  processed_retention_days = var.processed_retention_days
}

module "network" {
  source               = "./modules/network"
  name                 = local.name
  availability_zone    = local.availability_zone
  enable_telnet        = var.enable_telnet
  admin_cidr           = var.admin_cidr
  allowed_bucket_arns  = [module.storage.telemetry_bucket_arn, module.storage.artifacts_bucket_arn]
  flow_logs_bucket_arn = var.enable_flow_logs ? module.storage.telemetry_bucket_arn : null
}

module "honeypot" {
  source              = "./modules/honeypot"
  name                = local.name
  vpc_id              = module.network.vpc_id
  subnet_id           = module.network.subnet_id
  s3_prefix_list_id   = module.network.s3_prefix_list_id
  instance_type       = var.instance_type
  architecture        = var.architecture
  enable_telnet       = var.enable_telnet
  admin_cidr          = var.admin_cidr
  telemetry_bucket    = module.storage.telemetry_bucket
  artifacts_bucket    = module.storage.artifacts_bucket
  sensor_name         = var.sensor_name
  honeypot_image_path = var.honeypot_image_path

  # The instance must not boot before the endpoint exists, or it has no route to its artifacts.
  depends_on = [module.network]
}

module "pipeline" {
  source               = "./modules/pipeline"
  name                 = local.name
  telemetry_bucket     = module.storage.telemetry_bucket
  lambda_zip_path      = var.lambda_zip_path
  alert_email          = var.alert_email
  enable_notifications = var.enable_notifications
  log_retention_days   = var.log_retention_days
}

module "analytics" {
  source           = "./modules/analytics"
  name             = local.name
  telemetry_bucket = module.storage.telemetry_bucket
}

module "monitoring" {
  source             = "./modules/monitoring"
  name               = local.name
  project_tag        = var.project
  monthly_budget_usd = var.monthly_budget_usd
  account_budget_usd = var.account_budget_usd
  budget_email       = var.budget_email
  alarm_topic_arn    = module.pipeline.alerts_topic_arn
  function_names     = module.pipeline.function_names
  dlq_name           = module.pipeline.dlq_name
  instance_id        = module.honeypot.instance_id
}
