// Benchmarks and controls for specific services should override the "service" tag
locals {
  github_common_tags = {
    category = "Detection"
    plugin   = "github"
    service  = "GitHub"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  common_dimensions_audit_logs_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  action as operation,
  __RESOURCE_SQL__ as resource,
  actor as actor,
  tp_source_ip as source_ip,
  tp_index as organization,
  tp_id as source_id,
  *
  EOQ
}
