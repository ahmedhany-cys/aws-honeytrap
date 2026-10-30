# Two buckets:
#   telemetry - raw Cowrie logs (sensitive: contains attacker-typed passwords), processed
#               events/alerts, enrichment cache, evidence, Athena results, flow logs.
#   artifacts - honeypot container image and shipper script read by the instance at boot.
#
# Encryption: SSE-S3 (AES-256). SSE-KMS with a customer key would add $1/month per
# key plus request charges; see docs/cost-management.md for the trade-off.

locals {
  buckets = {
    telemetry = "${var.name}-telemetry-${var.account_id}"
    artifacts = "${var.name}-artifacts-${var.account_id}"
  }
}

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_145:SSE-S3 (AES-256) instead of SSE-KMS to avoid KMS key and request charges.
  #checkov:skip=CKV_AWS_18:Server access logging would double request volume; CloudTrail data events can be enabled if needed.
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles storage cost for disposable lab telemetry.
  #checkov:skip=CKV2_AWS_62:Telemetry bucket sends events to EventBridge (aws_s3_bucket_notification); the artifacts bucket has no consumers.
  #checkov:skip=CKV2_AWS_61:Both buckets have lifecycle configurations; Checkov cannot resolve them through for_each.
  for_each      = local.buckets
  bucket        = each.value
  force_destroy = var.force_destroy
  tags          = { Name = each.value, Purpose = each.key }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = aws_s3_bucket.this
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "bucket" {
  for_each = aws_s3_bucket.this

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOldTLS"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }

  dynamic "statement" {
    for_each = each.key == "telemetry" ? [1] : []
    content {
      sid       = "AllowVPCFlowLogsDelivery"
      effect    = "Allow"
      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/flowlogs/AWSLogs/${var.account_id}/*"]
      principals {
        type        = "Service"
        identifiers = ["delivery.logs.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
      condition {
        test     = "StringEquals"
        variable = "s3:x-amz-acl"
        values   = ["bucket-owner-full-control"]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "telemetry" ? [1] : []
    content {
      sid       = "AllowVPCFlowLogsAclCheck"
      effect    = "Allow"
      actions   = ["s3:GetBucketAcl"]
      resources = [each.value.arn]
      principals {
        type        = "Service"
        identifiers = ["delivery.logs.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  for_each   = aws_s3_bucket.this
  bucket     = each.value.id
  policy     = data.aws_iam_policy_document.bucket[each.key].json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

# Lifecycle: keep data only as long as it is useful, keep noncurrent versions briefly.
resource "aws_s3_bucket_lifecycle_configuration" "telemetry" {
  #checkov:skip=CKV_AWS_300:Every dynamic rule sets abort_incomplete_multipart_upload; Checkov does not expand dynamic blocks.
  bucket = aws_s3_bucket.this["telemetry"].id

  dynamic "rule" {
    for_each = {
      raw       = { prefix = "raw/", days = var.raw_retention_days }
      evidence  = { prefix = "evidence/", days = var.raw_retention_days }
      processed = { prefix = "processed/", days = var.processed_retention_days }
      athena    = { prefix = "athena-results/", days = 7 }
      flowlogs  = { prefix = "flowlogs/", days = var.flow_log_retention_days }
    }
    content {
      id     = "expire-${rule.key}"
      status = "Enabled"
      filter {
        prefix = rule.value.prefix
      }
      expiration {
        days = rule.value.days
      }
      noncurrent_version_expiration {
        noncurrent_days = 7
      }
      abort_incomplete_multipart_upload {
        days_after_initiation = 1
      }
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.this["artifacts"].id
  rule {
    id     = "noncurrent-cleanup"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# Object-created events go to EventBridge, which triggers the processor Lambda.
resource "aws_s3_bucket_notification" "telemetry" {
  bucket      = aws_s3_bucket.this["telemetry"].id
  eventbridge = true
}
