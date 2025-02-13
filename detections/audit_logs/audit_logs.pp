locals {
  github_workflow_run_failed_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "org")

  github_branch_protection_policy_override_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields ->> '$' ->> 'repo', '/commit/', additional_fields ->> '$' ->> 'after')")

  github_branch_protection_disabled_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'))")

  organization_authentication_method_updates_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org, '/settings/authentication')")

  github_organization_ip_allow_list_updated_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  github_organization_application_integration_updated_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  organization_moderator_updates_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', additional_fields::JSON ->> 'user')")

  github_organization_user_added_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  detect_audit_logs_with_public_repository_create_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  github_repository_archived_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  github_repository_collaborator_updates_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  repository_create_events_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  repository_visibility_changes_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  github_repository_vulnerability_alert_dismissed_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'), '/security/dependabot/', json_extract_string(additional_fields, '$.alert_number'))")
}

benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    detection.github_repository_vulnerability_alert_dismissed,
    detection.github_branch_protection_disabled,
    detection.github_branch_protection_policy_override,
    detection.github_organization_ip_allow_list_updated,
    detection.github_organization_saml_disabled,
    detection.github_organization_two_factor_disabled,
    detection.github_organization_user_added,
    detection.github_organization_user_removed,
    detection.github_repository_archived,
    detection.github_repository_collaborator_updates,
  ]

  tags = merge(local.github_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections and queries
 */

detection "github_branch_protection_policy_override" {
  title           = "GitHub Branch Protection Policy Override"
  description     = "Detect when a GitHub branch protection policy was overridden, potentially allowing unauthorized changes, force pushes, or unverified commits."
  severity        = "high"
  query           = query.github_branch_protection_policy_override
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "github_branch_protection_policy_override" {
  sql = <<-EOQ
    select
      ${local.github_branch_protection_policy_override_sql_columns}
    from
      github_audit_log
    where
      action = 'protected_branch.policy_override'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_branch_protection_disabled" {
  title           = "GitHub Branch Protection Disabled"
  description     = "Detect when branch protection was disabled, potentially exposing the repository to unauthorized changes or malicious commits."
  severity        = "high"
  # documentation   = file("./detections/audit_logs/docs/github_branch_protection_disabled.md")
  query           = query.github_branch_protection_disabled
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "github_branch_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.github_branch_protection_disabled_sql_columns}
    from
      github_audit_log
    where
      action = 'protected_branch.destroy'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_saml_disabled" {
  title           = "GitHub Organization SAML Disabled"
  description     = "Detect when SAML authentication was disabled for a GitHub organization, potentially allowing unauthorized access or weakening authentication controls."
  severity        = "critical"
  query           = query.github_organization_saml_disabled
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "github_organization_saml_disabled" {
  sql = <<-EOQ
    select
      ${local.organization_authentication_method_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'org.saml_disabled'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_two_factor_disabled" {
  title           = "GitHub Organization Two-Factor Authentication Disabled"
  description     = "Detect when two-factor authentication was disabled for a GitHub organization, potentially increasing the risk of unauthorized access."
  severity        = "critical"
  query           = query.github_organization_two_factor_disabled
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "github_organization_two_factor_disabled" {
  sql = <<-EOQ
    select
      ${local.organization_authentication_method_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'org.disable_two_factor_requirement'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_ip_allow_list_updated" {
  title           = "GitHub Organization IP Allow List Updated"
  description     = "Detect when changes were made to an organization's IP allow list, potentially indicating unauthorized network access modifications or security policy bypasses."
  severity        = "medium"
  query           = query.github_organization_ip_allow_list_updated
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "github_organization_ip_allow_list_updated" {
  sql = <<-EOQ
    select
      ${local.github_organization_ip_allow_list_updated_sql_columns}
    from
      github_audit_log
    where
      action in (
        'ip_allow_list.enable',
        'ip_allow_list.disable',
        'ip_allow_list.enable_for_installed_apps',
        'ip_allow_list.disable_for_installed_apps',
        'ip_allow_list_entry.create',
        'ip_allow_list_entry.update',
        'ip_allow_list_entry.destroy'
      )
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_moderator_added" {
  title           = "GitHub Organization Moderator Added"
  description     = "Detect when a Github Organization user was added as a moderator, potentially increasing their privileges."
  severity        = "medium"
  query           = query.github_organization_moderator_added
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "github_organization_moderator_added" {
  sql = <<-EOQ
    select
      ${local.organization_moderator_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'organization_moderators.add_user'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_moderator_removed" {
  title           = "GitHub Organization Moderator Removed"
  description     = "Detect when a Github Organization moderator was removed, potentially reducing oversight and security controls."
  severity        = "high"
  query           = query.github_organization_moderator_removed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "github_organization_moderator_removed" {
  sql = <<-EOQ
    select
      ${local.organization_moderator_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'organization_moderators.remove_user'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_user_added" {
  title           = "GitHub Organization User Added"
  description     = "Detect when a user was added to a GitHub organization, which may indicate a new access provision or a potential unauthorized account being added."
  severity        = "low"
  query           = query.github_organization_user_added
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "github_organization_user_added" {
  sql = <<-EOQ
    select
      ${local.github_organization_user_added_sql_columns}
    from
      github_audit_log
    where
      action = 'org.add_member'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_user_removed" {
  title           = "GitHub Organization User Removed"
  description     = "Detect when a user was removed from a GitHub organization, potentially indicating an access revocation or an unauthorized removal."
  severity        = "medium"
  query           = query.github_organization_user_removed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "github_organization_user_removed" {
  sql = <<-EOQ
    select
      ${local.github_organization_user_added_sql_columns}
    from
      github_audit_log
    where
      action = 'org.remove_member'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_application_installed" {
  title           = "GitHub Organization Application Installed"
  description     = "Detect when an application integration is installed in a GitHub organization, potentially introducing new permissions or external service access."
  severity        = "low"
  query           = query.github_organization_application_installed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "github_organization_application_installed" {
  sql = <<-EOQ
    select
      ${local.github_organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'integration_installation.create'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_application_removed" {
  title           = "GitHub Organization Application Removed"
  description     = "Detect when an application integration is removed from a GitHub organization, which may impact service dependencies or security controls."
  severity        = "medium"
  query           = query.github_organization_application_removed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098, TA0001:T1195.002"
  })
}

query "github_organization_application_removed" {
  sql = <<-EOQ
    select
      ${local.github_organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'integration_installation.delete'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_oauth_application_authorized" {
  title           = "GitHub Organization OAuth Application Authorized"
  description     = "Detect when an OAuth application is authorized in a GitHub organization, potentially granting external services access to organization data."
  severity        = "low"
  query           = query.github_organization_oauth_application_authorized
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "github_organization_oauth_application_authorized" {
  sql = <<-EOQ
    select
      ${local.github_organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'oauth_application.authorize'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_organization_oauth_application_revoked" {
  title           = "GitHub Organization OAuth Application Revoked"
  description     = "Detect when an OAuth application authorization is revoked in a GitHub organization, which may indicate security control enforcement or a misconfiguration."
  severity        = "medium"
  query           = query.github_organization_oauth_application_revoked
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098, TA0001:T1195.002"
  })
}

query "github_organization_oauth_application_revoked" {
  sql = <<-EOQ
    select
      ${local.github_organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'oauth_application.revoke'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_repository_archived" {
  title           = "GitHub Repository Archived"
  description     = "Detect when a GitHub repository was archived, potentially impacting repository accessibility and signaling a deprecation or maintenance decision."
  severity        = "low"
  query           = query.github_repository_archived
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "github_repository_archived" {
  sql = <<-EOQ
    select
      ${local.github_repository_archived_sql_columns}
    from
      github_audit_log
    where
      action = 'repo.archived'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

detection "github_repository_collaborator_updates" {
  title           = "Detect Repository Collaborator Updates"
  description     = "Detect actions where the repository collaborator list was modified, indicating potential changes in access permissions or security policies within the repository."
  severity        = "medium"
  query           = query.github_repository_collaborator_updates
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "github_repository_collaborator_updates" {
  sql = <<-EOQ
    select
      ${local.github_repository_collaborator_updates_sql_columns}
    from
      github_audit_log
    where
      action in ('repo.add_member', 'repo.remove_member')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "github_repository_vulnerability_alert_dismissed" {
  title           = "GitHub Repository Vulnerability Alert Dismissed"
  description     = "Detect when a repository vulnerability alert was dismissed, potentially ignoring critical security risks that may expose the repository to exploitation."
  severity        = "high"
  query           = query.github_repository_vulnerability_alert_dismissed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0010:T1567, TA0005:T1203, TA0005:T1190"
  })
}

query "github_repository_vulnerability_alert_dismissed" {
  sql = <<-EOQ
    select
      ${local.github_repository_vulnerability_alert_dismissed_sql_columns}
    from
      github_audit_log
    where
      action = 'repository_vulnerability_alert.dismiss'
      and actor NOT LIKE '%[bot]'
    order by
      tp_timestamp desc;
  EOQ
}

