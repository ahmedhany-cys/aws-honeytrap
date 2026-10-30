output "vpc_id" {
  value = aws_vpc.this.id
}

output "subnet_id" {
  value = aws_subnet.honeypot.id
}

output "s3_prefix_list_id" {
  description = "Managed prefix list of the regional S3 service, used as the only SG egress destination."
  value       = aws_vpc_endpoint.s3.prefix_list_id
}

output "s3_endpoint_id" {
  value = aws_vpc_endpoint.s3.id
}
