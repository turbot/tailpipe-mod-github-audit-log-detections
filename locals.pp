// Benchmarks and controls for specific services should override the "service" tag
locals {
  github_audit_log_detections_common_tags = {
    category = "Detections"
    plugin   = "github"
    service  = "GitHub/Audit"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  action as operation,
  __RESOURCE_SQL__ as resource,
  actor as actor,
  tp_source_ip as source_ip,
  tp_index as organization,
  repo as repository,
  tp_id as source_id,
  *
  EOQ

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
  detection_sql_resource_column_branch_protection_policy_override = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/', additional_fields ->> 'repo', '/commit/', additional_fields ->> 'after')")

  detection_sql_resource_column_branch_protection_disabled = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'))")

  detection_sql_resource_column_organization_authentication_method_updates = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/orgs/', org, '/settings/authentication')")

  detection_sql_resource_column_user = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/', actor)")

  detection_sql_resource_column_organization = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/orgs/', org)")

  detection_sql_resource_column_organization_moderator_updates = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/orgs/', additional_fields::JSON ->> 'user')")

  detection_sql_resource_column_repository = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/', additional_fields ->> 'repo')")

  detection_sql_resource_column_repository_vulnerability_alert_dismissed = replace(local.detection_sql_columns, "__RESOURCE_SQL__",
  "CONCAT('https://github.com/', additional_fields ->> 'repo', '/security/dependabot/', additional_fields ->> 'alert_number')")
}
