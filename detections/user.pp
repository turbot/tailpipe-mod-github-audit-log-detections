benchmark "user_detections" {
  title       = "User Detections"
  description = "This detection benchmark contains recommendations related to GitHub users."
  type        = "detection"
  children = [
    detection.user_authentication_failed
  ]

  tags = merge(local.github_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "user_authentication_failed" {
  title           = "User Authentication Failed"
  description     = "Detect when a user failed to authenticate, which may indicate unauthorized access attempts or credential stuffing attacks."
  documentation   = file("./detections/docs/user_authentication_failed.md")
  severity        = "medium"
  query           = query.user_authentication_failed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "User",
    service          = "GitHub/User",
    mitre_attack_ids = "TA0006:T1110"
  })
}

query "user_authentication_failed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action = 'user.failed_login'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder = "User",
    service = "GitHub/User"
  })
}