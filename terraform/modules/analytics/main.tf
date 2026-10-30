# Athena over the processed telemetry. Partition projection means no Glue crawler
# (and no crawler cost); the workgroup caps bytes scanned per query.

locals {
  location = "s3://${var.telemetry_bucket}/processed"
  projection = {
    "projection.enabled"       = "true"
    "projection.origin.type"   = "enum"
    "projection.origin.values" = "live,simulation,synthetic"
    "projection.dt.type"       = "date"
    "projection.dt.format"     = "yyyy-MM-dd"
    "projection.dt.range"      = "2026-01-01,NOW"
    "classification"           = "json"
  }
  event_columns = {
    event_id             = "string", timestamp = "string", event_type = "string", category = "string",
    session_id           = "string", src_ip = "string", src_port = "int", dst_port = "int", protocol = "string",
    sensor               = "string", data_origin = "string", username = "string", password_masked = "string",
    password_fingerprint = "string", password_length = "int", credential_fingerprint = "string",
    login_success        = "boolean", command = "string", url = "string", file_path = "string",
    file_sha256          = "string", duration_seconds = "double", client_version = "string", hassh = "string",
    tunnel_destination   = "string", message = "string"
  }
  alert_columns = {
    alert_id    = "string", rule_id = "string", rule_name = "string", severity = "string", entity = "string",
    src_ip      = "string", first_seen = "string", last_seen = "string", summary = "string",
    data_origin = "string", classification = "string", session_ids = "array<string>",
    related_ips = "array<string>", evidence_event_ids = "array<string>", severity_reasons = "array<string>",
    techniques  = "array<struct<technique_id:string,name:string,tactics:array<string>,url:string,confidence:string,evidence:array<string>>>"
  }
}

resource "aws_glue_catalog_database" "this" {
  name        = replace("${var.name}_db", "-", "_")
  description = "HoneyTrap processed telemetry"
}

resource "aws_glue_catalog_table" "events" {
  name          = "events"
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"
  parameters = merge(local.projection, {
    "storage.location.template" = "${local.location}/events/origin=$${origin}/dt=$${dt}/"
  })

  partition_keys {
    name = "origin"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "${local.location}/events/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "ignore.malformed.json" = "true" }
    }
    dynamic "columns" {
      for_each = local.event_columns
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}

resource "aws_glue_catalog_table" "alerts" {
  name          = "alerts"
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"
  parameters = merge(local.projection, {
    "storage.location.template" = "${local.location}/alerts/origin=$${origin}/dt=$${dt}/"
  })

  partition_keys {
    name = "origin"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "${local.location}/alerts/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "ignore.malformed.json" = "true" }
    }
    dynamic "columns" {
      for_each = local.alert_columns
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}

resource "aws_athena_workgroup" "this" {
  name          = "${var.name}-investigations"
  force_destroy = true
  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false
    bytes_scanned_cutoff_per_query     = var.bytes_scanned_cutoff
    result_configuration {
      output_location = "s3://${var.telemetry_bucket}/athena-results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

resource "aws_athena_named_query" "this" {
  for_each  = fileset("${path.module}/../../../athena/queries", "*.sql")
  name      = trimsuffix(each.value, ".sql")
  workgroup = aws_athena_workgroup.this.id
  database  = aws_glue_catalog_database.this.name
  query     = file("${path.module}/../../../athena/queries/${each.value}")
}
