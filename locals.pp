// Benchmarks and controls for specific services should override the "service" tag
locals {
  github_audit_log_detections_common_tags = {
    category = "Detections"
    plugin   = "github"
    service  = "GitHub/Organization"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  action as operation,
  __RESOURCE_SQL__ as resource,
  actor,
  tp_source_ip as source_ip,
  tp_index as organization,
  repo as repository,
  tp_id as source_id,
  *
  exclude (actor,timestamp)
  EOQ

  audit_log_organization_detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "organization",
    "source_id"
  ]

  audit_log_detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "organization",
    "repository",
    "source_id"
  ]
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_resource_column_repository_commit_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "concat('https://github.com/', additional_fields ->> 'repo', '/commit/', additional_fields ->> 'after')")

  detection_sql_resource_column_organization_authentication = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "concat('https://github.com/orgs/', org, '/settings/authentication')")

  detection_sql_resource_column_user = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "concat('https://github.com/', actor)")

  detection_sql_resource_column_organization = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "concat('https://github.com/orgs/', org)")

  detection_sql_resource_column_organization_user = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "concat('https://github.com/orgs/', additional_fields ->> 'user')")

  detection_sql_resource_column_repository = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "concat('https://github.com/', additional_fields ->> 'repo')")

  detection_sql_resource_column_repository_vulnerability_alert_number = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "concat('https://github.com/', additional_fields ->> 'repo', '/security/dependabot/', additional_fields ->> 'alert_number')")
}
