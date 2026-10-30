output "sensor_public_ip" {
  description = "Public IP of the decoy. Do NOT connect to it from your own machine except for authorised tests."
  value       = module.honeypot.public_ip
}

output "sensor_instance_id" {
  value = module.honeypot.instance_id
}

output "telemetry_bucket" {
  value = module.storage.telemetry_bucket
}

output "artifacts_bucket" {
  value = module.storage.artifacts_bucket
}

output "alerts_topic_arn" {
  value = module.pipeline.alerts_topic_arn
}

output "lambda_functions" {
  value = module.pipeline.function_names
}

output "athena_workgroup" {
  value = module.analytics.workgroup
}

output "athena_database" {
  value = module.analytics.database
}

output "api_key_parameters" {
  value = module.pipeline.api_key_parameters
}

output "dashboard_command" {
  description = "Run the dashboard locally against the deployed bucket (read-only use)."
  value       = "HONEYTRAP_DATA=s3://${module.storage.telemetry_bucket} streamlit run dashboard/app.py"
}
