# Lab deployment: one t3.micro sensor, SSH only, short retention.
environment        = "dev"
region             = "us-west-1"
instance_type      = "t3.micro"
architecture       = "x86_64"
sensor_name        = "honeytrap-aws-01"
enable_telnet      = false
enable_flow_logs   = true
monthly_budget_usd = 5
account_budget_usd = 10
raw_retention_days = 14
# budget_email     = "you@example.com"   # strongly recommended
# alert_email      = "you@example.com"
# admin_cidr       = "203.0.113.10/32"   # only if you need shell access to the host
