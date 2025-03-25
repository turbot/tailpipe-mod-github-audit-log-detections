locals {
  personal_access_token_common_tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Personal Access Token"
    service = "GitHub/PersonalAccessToken"
  })
}

benchmark "personal_access_token_detections" {
  title       = "Personal Access Token Detections"
  description = "This detection benchmark contains recommendations related to GitHub fine-grained personal access tokens."
  type        = "detection"
  children = [
    detection.personal_access_token_granted
  ]

  tags = merge(local.personal_access_token_common_tags, {
    type = "Benchmark"
  })
}

detection "personal_access_token_granted" {
  title           = "Personal Access Token Granted"
  description     = "Detect when a GitHub fine-grained personal access token (PAT) was granted access, potentially granting access to repositories, actions, or APIs."
  documentation   = file("./detections/docs/personal_access_token_granted.md")
  severity        = "medium"
  query           = query.personal_access_token_granted
  display_columns = local.detection_display_columns_repository

  tags = merge(local.personal_access_token_common_tags, {
    mitre_attack_ids = "TA0006:T1078.004"
  })
}

query "personal_access_token_granted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_personal_access_token_name}
    from
      github_audit_log
    where
      action in ('personal_access_token.access_granted')
    order by
      tp_timestamp desc;
  EOQ

  tags = local.personal_access_token_common_tags
}
