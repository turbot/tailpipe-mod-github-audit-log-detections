// Benchmarks and controls for specific services should override the "service" tag
locals {
  github_common_tags = {
    category = "Detection"
    plugin   = "github"
    service  = "GitHub/Audit"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  audit_log_detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  action as operation,
  __RESOURCE_SQL__ as resource,
  actor as actor,
  tp_source_ip as source_ip,
  tp_index as organization,
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
    "source_id"
  ]
}
