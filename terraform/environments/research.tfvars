# Longer-running research sensor: SSH + Telnet, longer retention. Higher volume
# (Telnet attracts Mirai-family botnets) means more S3 PUTs and Lambda invocations.
environment              = "research"
region                   = "us-west-1"
instance_type            = "t3.micro"
architecture             = "x86_64"
sensor_name              = "honeytrap-aws-02"
enable_telnet            = true
enable_flow_logs         = true
monthly_budget_usd       = 8
account_budget_usd       = 15
raw_retention_days       = 30
processed_retention_days = 180
