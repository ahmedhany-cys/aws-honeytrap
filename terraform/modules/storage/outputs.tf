output "telemetry_bucket" {
  value = aws_s3_bucket.this["telemetry"].id
}

output "telemetry_bucket_arn" {
  value = aws_s3_bucket.this["telemetry"].arn
}

output "artifacts_bucket" {
  value = aws_s3_bucket.this["artifacts"].id
}

output "artifacts_bucket_arn" {
  value = aws_s3_bucket.this["artifacts"].arn
}
