output "instance_id" {
  value = aws_instance.sensor.id
}

output "public_ip" {
  value = aws_instance.sensor.public_ip
}

output "security_group_id" {
  value = aws_security_group.honeypot.id
}

output "role_arn" {
  value = aws_iam_role.sensor.arn
}
