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

  # TODO: Add another local to split repo vs. org column set
  detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  action as operation,
  __RESOURCE_SQL__ as resource,
  actor,
  tp_source_ip as source_ip,
  tp_index as organization,
  split_part(repo, '/', 2) as repository,
  tp_id as source_id,
  *
  exclude (actor, timestamp)
  EOQ

  detection_display_columns_organization = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "organization",
    "source_id"
  ]

  detection_display_columns_repository = [
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
  detection_sql_resource_column_integration = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "additional_fields ->> 'integration'")
  detection_sql_resource_column_organization = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "concat('https://github.com/', org)")
  detection_sql_resource_column_personal_access_token_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "additional_fields ->> 'user_programmatic_access_name'")
  detection_sql_resource_column_repository = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "concat('https://github.com/', repo)")
  detection_sql_resource_column_repository_branch_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "concat('https://github.com/', repo, '/tree/', additional_fields ->> 'name')")
  detection_sql_resource_column_repository_commit_id = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "concat('https://github.com/', repo, '/commit/', additional_fields ->> 'after')")
  detection_sql_resource_column_repository_vulnerability_alert_number = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "concat('https://github.com/', repo, '/security/dependabot/', additional_fields ->> 'alert_number')")
  detection_sql_resource_column_user = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "concat('https://github.com/', user)")
}
