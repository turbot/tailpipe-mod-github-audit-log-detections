benchmark "branch_detections" {
  title       = "Branch Detections"
  description = "This detection benchmark contains recommendations related to branch protection."
  type        = "detection"
  children = [
    detection.branch_protection_disabled,
    detection.branch_protection_policy_overridden,
  ]

  tags = merge(local.github_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "branch_protection_policy_overridden" {
  title           = "Branch Protection Policy Overridden"
  description     = "Detect when a branch protection policy was overridden, potentially allowing unauthorized changes, force pushes, or unverified commits."
  documentation   = file("./detections/docs/branch_protection_policy_overridden.md")
  severity        = "high"
  query           = query.branch_protection_policy_overridden
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Branch",
    service          = "GitHub/Branch",
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "branch_protection_policy_overridden" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_repository_commit_id}
    from
      github_audit_log
    where
      action = 'protected_branch.policy_override'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Branch",
    service = "GitHub/Branch"
  })
}

detection "branch_protection_disabled" {
  title           = "Branch Protection Disabled"
  description     = "Detect when branch protection was disabled, potentially exposing the repository to unauthorized changes or malicious commits."
  documentation   = file("./detections/docs/branch_protection_disabled.md")
  severity        = "high"
  query           = query.branch_protection_disabled
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Branch",
    service          = "GitHub/Branch",
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "branch_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_repository}
    from
      github_audit_log
    where
      action = 'protected_branch.destroy'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Branch",
    service = "GitHub/Branch"
  })
}