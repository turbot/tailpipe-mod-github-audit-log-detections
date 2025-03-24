benchmark "repository_detections" {
  title       = "Repository Detections"
  description = "This detection benchmark contains recommendations related to GitHub repositories."
  type        = "detection"
  children = [
    detection.repository_archived,
    detection.repository_collaborator_list_updated,
    detection.repository_visibility_set_public,
    detection.repository_vulnerability_alert_dismissed,
  ]

  tags = merge(local.github_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "repository_archived" {
  title           = "Repository Archived"
  description     = "Detect when a GitHub repository was archived, potentially impacting repository accessibility and signaling a deprecation or maintenance decision."
  documentation   = file("./detections/docs/repository_archived.md")
  severity        = "low"
  query           = query.repository_archived
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Repository",
    service          = "GitHub/Repository",
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "repository_archived" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_repository}
    from
      github_audit_log
    where
      action = 'repo.archived'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Repository",
    service = "GitHub/Repository"
  })
}

detection "repository_collaborator_list_updated" {
  title           = "Repository Collaborator List Updated"
  description     = "Detect when the repository collaborator list was updated, indicating potential changes in access permissions or security policies within the repository."
  documentation   = file("./detections/docs/repository_collaborator_list_updated.md")
  severity        = "medium"
  query           = query.repository_collaborator_list_updated
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Repository",
    service          = "GitHub/Repository",
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "repository_collaborator_list_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_repository}
    from
      github_audit_log
    where
      action in ('repo.add_member', 'repo.remove_member')
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Repository",
    service = "GitHub/Repository"
  })
}

detection "repository_vulnerability_alert_dismissed" {
  title           = "Repository Vulnerability Alert Dismissed"
  description     = "Detect when a repository vulnerability alert was dismissed, potentially ignoring high security risks that may expose the repository to exploitation."
  documentation   = file("./detections/docs/repository_vulnerability_alert_dismissed.md")
  severity        = "high"
  query           = query.repository_vulnerability_alert_dismissed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Repository",
    service          = "GitHub/Repository",
    mitre_attack_ids = "TA0010:T1567, TA0005:T1203, TA0005:T1190"
  })
}

query "repository_vulnerability_alert_dismissed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_repository_vulnerability_alert_number}
    from
      github_audit_log
    where
      action = 'repository_vulnerability_alert.dismiss'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Repository",
    service = "GitHub/Repository"
  })
}

detection "repository_visibility_set_public" {
  title           = "Repository Visibility Set Public"
  description     = "Detect when a private repository's visibility was set to public, potentially exposing proprietary or sensitive code."
  documentation   = file("./detections/docs/repository_visibility_set_public.md")
  severity        = "high"
  query           = query.repository_visibility_set_public
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Repository",
    service          = "GitHub/Repository",
    mitre_attack_ids = "TA0001:T1195.002"
  })
}

query "repository_visibility_set_public" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_repository}
    from
      github_audit_log
    where
      action = 'repo.access'
      and (additional_fields ->> 'visibility') = 'public'
      and (additional_fields ->> 'previous_visibility') = 'private'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Repository",
    service = "GitHub/Repository"
  })
}