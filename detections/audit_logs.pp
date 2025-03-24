benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    benchmark.branch_detections,
    benchmark.organization_detections,
    benchmark.personal_access_token_detections,
    benchmark.repository_detections,
    benchmark.user_detections,
  ]

  tags = merge(local.github_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}