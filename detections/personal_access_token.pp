benchmark "personal_access_token_detections" {
  title       = "Personal Access Token Detections"
  description = "This detection benchmark contains recommendations related to GitHub personal access tokens."
  type        = "detection"
  children = [
    detection.personal_access_token_created
  ]

  tags = merge(local.github_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "personal_access_token_created" {
  title           = "Personal Access Token Created"
  description     = "Detect when a GitHub personal access token (PAT) was created, potentially granting access to repositories, actions, or APIs."
  documentation   = file("./detections/docs/personal_access_token_created.md")
  severity        = "medium"
  query           = query.personal_access_token_created
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Personal Access Token",
    service          = "GitHub/PersonalAccessToken",
    mitre_attack_ids = "TA0006:T1078.004"
  })
}

query "personal_access_token_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action in ('personal_access_token.create', 'personal_access_token.request_created', 'personal_access_token.access_granted')
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder = "GitHub/PersonalAccessToken"
  })
}