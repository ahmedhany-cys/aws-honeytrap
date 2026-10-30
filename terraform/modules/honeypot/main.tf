# The sensor: one EC2 instance running Cowrie in a hardened container.
#
# Isolation layers (outside -> in):
#   1. Security group: ingress 22 (+23 optional), egress ONLY HTTPS to the S3 prefix list.
#   2. S3 gateway endpoint policy: only HoneyTrap buckets + Amazon Linux repos.
#   3. Host iptables (DOCKER-USER): the container may not open ANY outbound connection,
#      including DNS and the instance metadata service.
#   4. IMDSv2 required with hop limit 1: containers cannot obtain instance credentials.
#   5. Container: non-root, read-only rootfs, all capabilities dropped,
#      no-new-privileges, memory/pid limits. Cowrie is an emulator; attacker input is
#      never executed by a real shell.
#   6. IAM: the instance can only PutObject under raw/origin=live/sensor=<name>/ and
#      evidence/, and read its two boot artifacts. No other AWS access.

data "aws_region" "current" {}

data "aws_ssm_parameter" "al2023_ami" {
  name = var.architecture == "arm64" ? "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64" : "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# --------------------------------------------------------------------------- artifacts
resource "aws_s3_object" "image" {
  bucket = var.artifacts_bucket
  key    = "honeypot/cowrie-image.tar.gz"
  source = var.honeypot_image_path
  etag   = filemd5(var.honeypot_image_path)
}

resource "aws_s3_object" "shipper" {
  bucket = var.artifacts_bucket
  key    = "honeypot/shipper.py"
  source = "${path.module}/../../../honeypot/shipper/shipper.py"
  etag   = filemd5("${path.module}/../../../honeypot/shipper/shipper.py")
}

# --------------------------------------------------------------------------- security group
resource "aws_security_group" "honeypot" {
  name        = "${var.name}-honeypot"
  description = "HoneyTrap sensor: decoy ports in, S3 endpoint only out"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-honeypot-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  #checkov:skip=CKV_AWS_24:Port 22 open to the world is the purpose of an SSH honeypot; it is served by Cowrie, not sshd.
  security_group_id = aws_security_group.honeypot.id
  description       = "Decoy SSH (Cowrie)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}

resource "aws_vpc_security_group_ingress_rule" "telnet" {
  count             = var.enable_telnet ? 1 : 0
  security_group_id = aws_security_group.honeypot.id
  description       = "Decoy Telnet (Cowrie)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 23
  to_port           = 23
}

resource "aws_vpc_security_group_ingress_rule" "admin" {
  count             = var.admin_cidr == null ? 0 : 1
  security_group_id = aws_security_group.honeypot.id
  description       = "Real sshd for the operator only"
  cidr_ipv4         = var.admin_cidr
  ip_protocol       = "tcp"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
}

resource "aws_vpc_security_group_egress_rule" "s3" {
  security_group_id = aws_security_group.honeypot.id
  description       = "HTTPS to S3 via the gateway endpoint only"
  prefix_list_id    = var.s3_prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# --------------------------------------------------------------------------- IAM
data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "sensor" {
  statement {
    sid     = "ShipTelemetry"
    actions = ["s3:PutObject"]
    resources = [
      "arn:aws:s3:::${var.telemetry_bucket}/raw/origin=live/sensor=${var.sensor_name}/*",
      "arn:aws:s3:::${var.telemetry_bucket}/evidence/tty/${var.sensor_name}/*",
      "arn:aws:s3:::${var.telemetry_bucket}/evidence/files/${var.sensor_name}/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }
  statement {
    sid     = "ReadBootArtifacts"
    actions = ["s3:GetObject"]
    resources = [
      "arn:aws:s3:::${var.artifacts_bucket}/${aws_s3_object.image.key}",
      "arn:aws:s3:::${var.artifacts_bucket}/${aws_s3_object.shipper.key}",
    ]
  }
}

resource "aws_iam_role" "sensor" {
  name               = "${var.name}-sensor"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy" "sensor" {
  name   = "ship-telemetry-only"
  role   = aws_iam_role.sensor.id
  policy = data.aws_iam_policy_document.sensor.json
}

resource "aws_iam_instance_profile" "sensor" {
  name = "${var.name}-sensor"
  role = aws_iam_role.sensor.name
}

# --------------------------------------------------------------------------- instance
resource "aws_instance" "sensor" {
  #checkov:skip=CKV_AWS_88:The decoy must have a public IP to receive internet attacks.
  #checkov:skip=CKV_AWS_126:Detailed monitoring is billed; basic 5-minute metrics drive the status-check alarm.
  ami                         = data.aws_ssm_parameter.al2023_ami.value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.honeypot.id]
  iam_instance_profile        = aws_iam_instance_profile.sensor.name
  associate_public_ip_address = true
  monitoring                  = false # detailed monitoring is billed; basic 5-minute metrics are free
  ebs_optimized               = true
  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region           = data.aws_region.current.region
    artifacts_bucket = var.artifacts_bucket
    image_key        = aws_s3_object.image.key
    image_etag       = aws_s3_object.image.etag
    shipper_key      = aws_s3_object.shipper.key
    telemetry_bucket = var.telemetry_bucket
    sensor_name      = var.sensor_name
    enable_telnet    = var.enable_telnet
    admin_enabled    = var.admin_cidr != null
    admin_ssh_port   = var.admin_ssh_port
    ship_interval    = var.ship_interval_minutes
  })

  # Unlimited mode can bill for surplus CPU credits; standard mode cannot.
  credit_specification {
    cpu_credits = "standard"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  tags = { Name = "${var.name}-sensor", Role = "honeypot" }

  lifecycle {
    precondition {
      condition     = contains(["t3.micro", "t4g.micro", "t3.small", "t4g.small", "t2.micro"], var.instance_type)
      error_message = "Only Free Tier eligible micro/small instance types are allowed for the sensor."
    }
  }
}
