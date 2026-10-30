# Cost guardrails and pipeline health alarms.
#
# NOTE: a budget notification does NOT stop spending. It only emails you.
# Teardown (scripts/teardown.sh) is the only thing that stops cost.

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly-cost"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = [format("user:Project$%s", var.project_tag)]
  }

  dynamic "notification" {
    for_each = var.budget_email == "" ? [] : [
      { type = "ACTUAL", threshold = 25 },
      { type = "ACTUAL", threshold = 80 },
      { type = "FORECASTED", threshold = 100 },
    ]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.budget_email]
    }
  }
}

# Account-wide budget as well: tag-based filtering misses untagged charges
# (e.g. data transfer), so this catches anything the project budget cannot see.
resource "aws_budgets_budget" "account" {
  name         = "${var.name}-account-guardrail"
  budget_type  = "COST"
  limit_amount = tostring(var.account_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = var.budget_email == "" ? [] : [1]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 50
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.budget_email]
    }
  }
}

# --------------------------------------------------------------------------- alarms (10 alarms are free)
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each            = var.function_names
  alarm_name          = "${each.value}-errors"
  alarm_description   = "HoneyTrap ${each.key} Lambda is failing"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name}-pipeline-dlq-not-empty"
  alarm_description   = "Events failed processing and landed in the DLQ"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = var.dlq_name }
  statistic           = "Maximum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "sensor_status" {
  alarm_name          = "${var.name}-sensor-status-check"
  alarm_description   = "Honeypot instance failed EC2 status checks"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  dimensions          = { InstanceId = var.instance_id }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [var.alarm_topic_arn]
}

# Silence is a signal: an internet-facing SSH honeypot normally sees traffic within
# minutes. No processed events for 3 hours means the sensor or shipper is broken.
resource "aws_cloudwatch_metric_alarm" "no_telemetry" {
  alarm_name          = "${var.name}-no-telemetry"
  alarm_description   = "No honeypot events processed for 3 hours"
  namespace           = "HoneyTrap"
  metric_name         = "EventsProcessed"
  dimensions          = { Function = "processor" }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [var.alarm_topic_arn]
}
