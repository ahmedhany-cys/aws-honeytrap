# Dedicated, isolated VPC for the honeypot.
#
# * One public subnet (the sensor must be reachable from the internet).
# * No NAT gateway, no peering, no transit gateway, no VPN: nothing routes to any
#   other environment.
# * The only private path out is the S3 gateway endpoint, whose policy allows
#   only the HoneyTrap buckets and the Amazon Linux 2023 package repository.

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = false
  tags                 = { Name = "${var.name}-vpc" }
}

# Remove all rules from the default security group so nothing can accidentally use it.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-default-sg-locked" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "honeypot" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.subnet_cidr
  availability_zone = var.availability_zone
  # Public IPs are assigned explicitly on the instance, not by subnet default.
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-honeypot-subnet", Tier = "deception" }
}

resource "aws_route_table" "honeypot" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-honeypot-rt" }
}

# Needed so attackers' TCP sessions can be answered. Outbound *initiation* is
# blocked by the security group (egress = S3 prefix list only) and on the host.
resource "aws_route" "internet" {
  route_table_id         = aws_route_table.honeypot.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "honeypot" {
  subnet_id      = aws_subnet.honeypot.id
  route_table_id = aws_route_table.honeypot.id
}

# --------------------------------------------------------------------------- NACL
# Stateless second layer. Inbound: decoy ports + ephemeral replies. Outbound:
# replies to attackers (ephemeral) and HTTPS (S3 endpoint). The security group
# narrows HTTPS further to the S3 prefix list.
resource "aws_network_acl" "honeypot" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.honeypot.id]
  tags       = { Name = "${var.name}-honeypot-nacl" }
}

resource "aws_network_acl_rule" "in_ssh" {
  #checkov:skip=CKV_AWS_232:Decoy SSH must be reachable from the internet; served by Cowrie, not sshd.
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "in_telnet" {
  count          = var.enable_telnet ? 1 : 0
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 23
  to_port        = 23
}

resource "aws_network_acl_rule" "in_admin" {
  count          = var.admin_cidr == null ? 0 : 1
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.admin_cidr
  from_port      = var.admin_ssh_port
  to_port        = var.admin_ssh_port
}

# Return traffic for the instance's own HTTPS calls to S3. Linux uses 32768-60999
# as its client port range, so the inbound window never covers service ports.
resource "aws_network_acl_rule" "in_ephemeral" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 32768
  to_port        = 65535
}

resource "aws_network_acl_rule" "out_ephemeral" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "out_https" {
  network_acl_id = aws_network_acl.honeypot.id
  rule_number    = 110
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# --------------------------------------------------------------------------- S3 gateway endpoint (free)
data "aws_iam_policy_document" "s3_endpoint" {
  #checkov:skip=CKV_AWS_283:Gateway endpoint policies require Principal "*"; access is narrowed by bucket ARN and, for our buckets, to principals of this account. The AL2023 repo is read anonymously by dnf, so it cannot carry a principal condition.
  statement {
    sid       = "HoneyTrapBuckets"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = flatten([for arn in var.allowed_bucket_arns : [arn, "${arn}/*"]])
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid       = "AmazonLinux2023Repos"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::al2023-repos-${data.aws_region.current.region}-de612dc2", "arn:aws:s3:::al2023-repos-${data.aws_region.current.region}-de612dc2/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.honeypot.id]
  policy            = data.aws_iam_policy_document.s3_endpoint.json
  tags              = { Name = "${var.name}-s3-endpoint" }
}

# --------------------------------------------------------------------------- VPC flow logs (optional)
resource "aws_flow_log" "this" {
  count                    = var.enable_flow_logs ? 1 : 0
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${var.flow_logs_bucket_arn}/flowlogs/"
  max_aggregation_interval = 600
  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = false
  }
  tags = { Name = "${var.name}-flow-logs" }
}
