output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "function_names" {
  value = { for k, f in aws_lambda_function.this : k => f.function_name }
}

output "dlq_name" {
  value = aws_sqs_queue.dlq.name
}

output "api_key_parameters" {
  description = "Set these SecureStrings to enable AbuseIPDB / VirusTotal enrichment."
  value       = [for p in aws_ssm_parameter.api_keys : p.name]
}
