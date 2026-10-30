# Event-driven detection pipeline.
#
#   shipper --PutObject raw/...--> S3 --Object Created--> EventBridge --> processor Lambda
#   EventBridge schedule (hourly) ----------------------------------> correlator Lambda
#   both Lambdas --> processed/* in S3, alerts >= threshold --> SNS
#
# Lambdas run outside a VPC on purpose: a VPC Lambda would need NAT or interface
# endpoints (paid) to reach S3/SNS/SSM and the enrichment APIs.

locals {
  telemetry_arn = "arn:aws:s3:::${var.telemetry_bucket}"
  param_prefix  = "/${var.name}"
  functions = {
    processor = {
      handler     = "handlers.processor.handler"
      timeout     = 120
      description = "Parse, detect, enrich and alert on new raw Cowrie batches"
    }
    correlator = {
      handler     = "handlers.correlator.handler"
      timeout     = 300
      description = "Hourly cross-batch correlation and attacker profiles"
    }
  }
}

# --------------------------------------------------------------------------- secrets (SSM SecureString)
resource "random_password" "hmac" {
  length  = 48
  special = false
}

resource "aws_ssm_parameter" "hmac" {
  #checkov:skip=CKV_AWS_337:Uses the AWS managed aws/ssm key; a customer managed key costs $1/month (see docs/cost-management.md).
  name        = "${local.param_prefix}/hmac-key"
  description = "Key for HMAC fingerprints of attacker-supplied passwords"
  type        = "SecureString"
  value       = random_password.hmac.result
}

# Optional API keys. Terraform creates placeholders; set real values out of band:
#   aws ssm put-parameter --overwrite --type SecureString --name /<name>/abuseipdb-api-key --value <key>
resource "aws_ssm_parameter" "api_keys" {
  #checkov:skip=CKV_AWS_337:Uses the AWS managed aws/ssm key; a customer managed key costs $1/month.
  for_each    = toset(["abuseipdb-api-key", "virustotal-api-key"])
  name        = "${local.param_prefix}/${each.key}"
  description = "Optional threat-intel API key ('unset' = integration disabled)"
  type        = "SecureString"
  value       = "unset"
  lifecycle {
    ignore_changes = [value]
  }
}

# --------------------------------------------------------------------------- SNS
resource "aws_sns_topic" "alerts" {
  name              = "${var.name}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --------------------------------------------------------------------------- DLQ for failed async invocations
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-pipeline-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

data "aws_iam_policy_document" "dlq" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.raw_object.arn, aws_cloudwatch_event_rule.hourly.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

# --------------------------------------------------------------------------- IAM (one role per function)
data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda" {
  for_each = local.functions

  statement {
    sid       = "ReadRaw"
    actions   = ["s3:GetObject"]
    resources = ["${local.telemetry_arn}/raw/*", "${local.telemetry_arn}/processed/*"]
  }
  statement {
    sid       = "WriteProcessed"
    actions   = ["s3:PutObject"]
    resources = ["${local.telemetry_arn}/processed/*"]
  }
  statement {
    sid       = "ListProcessed"
    actions   = ["s3:ListBucket"]
    resources = [local.telemetry_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["processed/*", "raw/*"]
    }
  }
  statement {
    sid       = "Secrets"
    actions   = ["ssm:GetParameter"]
    resources = concat([aws_ssm_parameter.hmac.arn], [for p in aws_ssm_parameter.api_keys : p.arn])
  }
  statement {
    sid       = "Alerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda[each.key].arn}:*"]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"] # X-Ray does not support resource-level permissions
  }
}

resource "aws_iam_role" "lambda" {
  for_each           = local.functions
  name               = "${var.name}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

resource "aws_iam_role_policy" "lambda" {
  for_each = local.functions
  name     = "least-privilege"
  role     = aws_iam_role.lambda[each.key].id
  policy   = data.aws_iam_policy_document.lambda[each.key].json
}

# --------------------------------------------------------------------------- functions
resource "aws_cloudwatch_log_group" "lambda" {
  #checkov:skip=CKV_AWS_338:Operational logs only; 14-day retention is a cost and data-minimisation choice. Evidence lives in S3.
  #checkov:skip=CKV_AWS_158:Log groups are encrypted at rest by CloudWatch; a KMS CMK adds monthly cost.
  for_each          = local.functions
  name              = "/aws/lambda/${var.name}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "this" {
  #checkov:skip=CKV_AWS_117:Not in a VPC - a VPC Lambda would need NAT or paid interface endpoints to reach S3/SNS/SSM and the TI APIs.
  #checkov:skip=CKV_AWS_173:Environment variables hold only resource names; secrets live in SSM SecureString.
  #checkov:skip=CKV_AWS_115:New accounts have an account concurrency of 10; reserving concurrency is not possible.
  #checkov:skip=CKV_AWS_272:Code signing needs AWS Signer profiles; the package is built reproducibly in CI instead.
  for_each         = local.functions
  function_name    = "${var.name}-${each.key}"
  description      = each.value.description
  role             = aws_iam_role.lambda[each.key].arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = each.value.handler
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  timeout          = each.value.timeout
  memory_size      = 256

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      TELEMETRY_BUCKET        = var.telemetry_bucket
      SNS_TOPIC_ARN           = var.enable_notifications ? aws_sns_topic.alerts.arn : ""
      HMAC_KEY_PARAM          = aws_ssm_parameter.hmac.name
      ABUSEIPDB_KEY_PARAM     = aws_ssm_parameter.api_keys["abuseipdb-api-key"].name
      VIRUSTOTAL_KEY_PARAM    = aws_ssm_parameter.api_keys["virustotal-api-key"].name
      ENRICHMENT_LOOKUP_LIMIT = tostring(var.enrichment_lookup_limit)
      CORRELATION_HOURS       = "24"
      LOG_LEVEL               = "INFO"
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

# The Lambda DLQ needs SendMessage from the function role.
resource "aws_iam_role_policy" "dlq" {
  for_each = local.functions
  name     = "dead-letter-queue"
  role     = aws_iam_role.lambda[each.key].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.dlq.arn }]
  })
}

resource "aws_lambda_function_event_invoke_config" "this" {
  for_each                     = local.functions
  function_name                = aws_lambda_function.this[each.key].function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
}

# --------------------------------------------------------------------------- EventBridge
resource "aws_cloudwatch_event_rule" "raw_object" {
  name        = "${var.name}-raw-object-created"
  description = "New raw Cowrie batch uploaded by the shipper"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = { name = [var.telemetry_bucket] }
      object = { key = [{ prefix = "raw/" }] }
    }
  })
}

resource "aws_cloudwatch_event_target" "raw_object" {
  rule = aws_cloudwatch_event_rule.raw_object.name
  arn  = aws_lambda_function.this["processor"].arn
  retry_policy {
    maximum_retry_attempts       = 3
    maximum_event_age_in_seconds = 3600
  }
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_cloudwatch_event_rule" "hourly" {
  name                = "${var.name}-hourly-correlation"
  description         = "Hourly correlation pass"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "hourly" {
  rule = aws_cloudwatch_event_rule.hourly.name
  arn  = aws_lambda_function.this["correlator"].arn
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "events" {
  for_each = {
    processor  = aws_cloudwatch_event_rule.raw_object.arn
    correlator = aws_cloudwatch_event_rule.hourly.arn
  }
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value
}
