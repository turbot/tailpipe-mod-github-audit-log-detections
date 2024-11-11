detection_benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    detection.audit_logs_github_action_failed,
    detection.audit_logs_github_branch_protection_policy_override,
    detection.audit_logs_github_branch_protection_disabled,
    detection.audit_logs_github_organization_authentication_method_update,
  ]

  # tags = merge(local.audit_logs_common_tags, {
  #   type = "Benchmark"
  # })
}

/*
 * Detections
 */

detection "audit_logs_github_action_failed" {
  title       = "Detect Failed GitHub Actions in Audit Logs"
  description = "Detect GitHub action failures in audit logs."
  severity    = "high"
  query       = query.audit_logs_github_action_failed

  references = [
    "https://docs.github.com/en/actions/creating-actions/setting-exit-codes-for-actions#about-exit-codes",
  ]

  # tags = merge(local.audit_logs_common_tags, {
  #   mitre_attack_ids = "TA0005:T1562:001"
  # })
}

detection "audit_logs_github_branch_protection_policy_override" {
  title       = "Detect GitHub Branch Protection Policy Overrides in Audit Logs"
  description = "Detect GitHub branch protection policy overrides in audit logs."
  severity    = "high"
  query       = query.audit_logs_github_branch_protection_policy_override

  references = [
    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule",
  ]

  # tags = merge(local.audit_logs_common_tags, {
  #   mitre_attack_ids = "TA0005:T1562:001"
  # })
}

detection "audit_logs_github_branch_protection_disabled" {
  title       = "Detect Disabling of GitHub Branch Protection Rules in Audit Logs"
  description = "Identifies actions in GitHub audit logs where branch protection rules are overridden or disabled, which may indicate unauthorized or risky modifications to repository protections."
  severity    = "high"
  query       = query.audit_logs_github_branch_protection_disabled

  references = [
    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule",
  ]

  # tags = merge(local.audit_logs_common_tags, {
  #   mitre_attack_ids = "TA0005:T1562:001"
  # })
}

detection "audit_logs_github_organization_authentication_method_update" {
  title       = "Detects Changes to GitHub Organization Authentication in Audit Logs"
  description = "Identifies actions in GitHub audit logs where updates are made to the GitHub organization's authentication methods."
  severity    = "critical"
  query       = query.audit_logs_github_organization_authentication_method_update

  references = [
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
  ]

  # tags = merge(local.audit_logs_common_tags, {
  #   mitre_attack_ids = "TA0005:T1562:001"
  # })
}

/*
 * Queries
 */

query "audit_logs_github_action_failed" {
  sql = <<-EOQ
    select
      actor,
      action,
      tp_timestamp,
      tp_date
    from
      github_audit_log
    where
      action = 'workflows.completed_workflow_run'
    order by
      tp_timestamp desc;
  EOQ
}

query "audit_logs_github_branch_protection_policy_override" {
  sql = <<-EOQ
    select
      actor,
      action,
      tp_timestamp,
      tp_date
    from
      github_audit_log
    where
      action = 'protected_branch.policy_override'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

query "audit_logs_github_branch_protection_disabled" {
  sql = <<-EOQ
    select
      actor,
      action,
      tp_timestamp,
      tp_date
    from
      github_audit_log
    where
      action = 'protected_branch.destroy'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

query "audit_logs_github_organization_authentication_method_update" {
  sql = <<-EOQ
    select
      actor,
      action,
      tp_timestamp,
      tp_date
    from
      github_audit_log
    where
      action in (
    'org.saml_disabled',
    'org.saml_enabled',
    'org.disable_two_factor_requirement',
    'org.enable_two_factor_requirement',
    'org.update_saml_provider_settings',
    'org.enable_oauth_app_restrictions',
    'org.disable_oauth_app_restrictions'
    )
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

