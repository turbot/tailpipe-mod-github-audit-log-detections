locals {
  workflow_run_failed_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "org")

  branch_protection_policy_override_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields ->> '$' ->> 'repo', '/commit/', additional_fields ->> '$' ->> 'after')")

  branch_protection_disabled_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'))")

  organization_authentication_method_updates_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org, '/settings/authentication')")

  organization_ip_allow_list_updated_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  organization_application_integration_updated_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  organization_moderator_updates_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', additional_fields::JSON ->> 'user')")

  organization_user_added_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  detect_audit_logs_with_public_repository_create_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  repository_archived_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  repository_collaborator_updates_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  repository_create_events_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  repository_visibility_changes_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  repository_vulnerability_alert_dismissed_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'), '/security/dependabot/', json_extract_string(additional_fields, '$.alert_number'))")
}

// Add public repo creation events
// 
benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    detection.branch_protection_disabled,
    detection.branch_protection_policy_override,
    detection.organization_application_installed,
    detection.organization_application_removed,
    detection.organization_ip_allow_list_updated,
    detection.organization_moderator_added,
    detection.organization_moderator_removed,
    detection.organization_oauth_application_authorized,
    detection.organization_oauth_application_revoked,
    detection.organization_ownership_transferred,
    detection.organization_saml_disabled,
    detection.organization_two_factor_authentication_disabled,
    detection.organization_user_added,
    detection.organization_user_removed,
    detection.personal_access_token_created,
    detection.repository_archived,
    detection.repository_collaborator_updates,
    detection.repository_visibility_set_public,
    detection.repository_vulnerability_alert_dismissed,
    detection.user_authentication_failed,
    detection.user_promoted_to_admin,
  ]

  tags = merge(local.github_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections and queries
 */

detection "branch_protection_policy_override" {
  title           = "Branch Protection Policy Override"
  description     = "Detect when a branch protection policy was overridden, potentially allowing unauthorized changes, force pushes, or unverified commits."
  severity        = "high"
  query           = query.branch_protection_policy_override
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "branch_protection_policy_override" {
  sql = <<-EOQ
    select
      ${local.branch_protection_policy_override_sql_columns}
    from
      github_audit_log
    where
      action = 'protected_branch.policy_override'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "branch_protection_disabled" {
  title       = "Branch Protection Disabled"
  description = "Detect when branch protection was disabled, potentially exposing the repository to unauthorized changes or malicious commits."
  severity    = "high"
  # documentation   = file("./detections/audit_logs/docs/branch_protection_disabled.md")
  query           = query.branch_protection_disabled
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "branch_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.branch_protection_disabled_sql_columns}
    from
      github_audit_log
    where
      action = 'protected_branch.destroy'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_saml_disabled" {
  title           = "Organization SAML Disabled"
  description     = "Detect when SAML authentication was disabled for a GitHub organization, potentially allowing unauthorized access or weakening authentication controls."
  severity        = "critical"
  query           = query.organization_saml_disabled
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_saml_disabled" {
  sql = <<-EOQ
    select
      ${local.organization_authentication_method_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'org.saml_disabled'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_two_factor_authentication_disabled" {
  title           = "Organization Two-Factor Authentication Disabled"
  description     = "Detect when two-factor authentication was disabled for a GitHub organization, potentially increasing the risk of unauthorized access."
  severity        = "critical"
  query           = query.organization_two_factor_authentication_disabled
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_two_factor_authentication_disabled" {
  sql = <<-EOQ
    select
      ${local.organization_authentication_method_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'org.disable_two_factor_requirement'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_ip_allow_list_updated" {
  title           = "Organization IP Allow List Updated"
  description     = "Detect when changes were made to an organization's IP allow list, potentially indicating unauthorized network access modifications or security policy bypasses."
  severity        = "medium"
  query           = query.organization_ip_allow_list_updated
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_ip_allow_list_updated" {
  sql = <<-EOQ
    select
      ${local.organization_ip_allow_list_updated_sql_columns}
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
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_moderator_added" {
  title           = "Organization Moderator Added"
  description     = "Detect when a user was added as a moderator in an organization, potentially increasing their privileges."
  severity        = "medium"
  query           = query.organization_moderator_added
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_moderator_added" {
  sql = <<-EOQ
    select
      ${local.organization_moderator_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'organization_moderators.add_user'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_moderator_removed" {
  title           = "Organization Moderator Removed"
  description     = "Detect when an organization's moderator was removed, potentially reducing oversight and security controls."
  severity        = "high"
  query           = query.organization_moderator_removed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_moderator_removed" {
  sql = <<-EOQ
    select
      ${local.organization_moderator_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'organization_moderators.remove_user'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_user_added" {
  title           = "Organization User Added"
  description     = "Detect when a user was added to a GitHub organization, which may indicate a new access provision or a potential unauthorized account being added."
  severity        = "low"
  query           = query.organization_user_added
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "organization_user_added" {
  sql = <<-EOQ
    select
      ${local.organization_user_added_sql_columns}
    from
      github_audit_log
    where
      action = 'org.add_member'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_user_removed" {
  title           = "Organization User Removed"
  description     = "Detect when a user was removed from a GitHub organization, potentially indicating an access revocation or an unauthorized removal."
  severity        = "medium"
  query           = query.organization_user_removed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "organization_user_removed" {
  sql = <<-EOQ
    select
      ${local.organization_user_added_sql_columns}
    from
      github_audit_log
    where
      action = 'org.remove_member'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_application_installed" {
  title           = "Organization Application Installed"
  description     = "Detect when an application integration was installed in a GitHub organization, potentially introducing new permissions or external service access."
  severity        = "low"
  query           = query.organization_application_installed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_application_installed" {
  sql = <<-EOQ
    select
      ${local.organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'integration_installation.create'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_application_removed" {
  title           = "Organization Application Removed"
  description     = "Detect when an application integration was removed from a GitHub organization, which may impact service dependencies or security controls."
  severity        = "medium"
  query           = query.organization_application_removed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098, TA0001:T1195.002"
  })
}

query "organization_application_removed" {
  sql = <<-EOQ
    select
      ${local.organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'integration_installation.delete'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_oauth_application_authorized" {
  title           = "Organization OAuth Application Authorized"
  description     = "Detect when an OAuth application was authorized in a GitHub organization, potentially granting external services access to organization data."
  severity        = "low"
  query           = query.organization_oauth_application_authorized
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_oauth_application_authorized" {
  sql = <<-EOQ
    select
      ${local.organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'oauth_application.authorize'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_oauth_application_revoked" {
  title           = "Organization OAuth Application Revoked"
  description     = "Detect when an OAuth application authorization was revoked in a GitHub organization, which may indicate security control enforcement or a misconfiguration."
  severity        = "medium"
  query           = query.organization_oauth_application_revoked
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098, TA0001:T1195.002"
  })
}

query "organization_oauth_application_revoked" {
  sql = <<-EOQ
    select
      ${local.organization_application_integration_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'oauth_application.revoke'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "repository_archived" {
  title           = "GitHub Repository Archived"
  description     = "Detect when a GitHub repository was archived, potentially impacting repository accessibility and signaling a deprecation or maintenance decision."
  severity        = "low"
  query           = query.repository_archived
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "repository_archived" {
  sql = <<-EOQ
    select
      ${local.repository_archived_sql_columns}
    from
      github_audit_log
    where
      action = 'repo.archived'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "repository_collaborator_updates" {
  title           = "Detect Repository Collaborator Updates"
  description     = "Detect actions where the repository collaborator list was modified, indicating potential changes in access permissions or security policies within the repository."
  severity        = "medium"
  query           = query.repository_collaborator_updates
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "repository_collaborator_updates" {
  sql = <<-EOQ
    select
      ${local.repository_collaborator_updates_sql_columns}
    from
      github_audit_log
    where
      action in ('repo.add_member', 'repo.remove_member')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "repository_vulnerability_alert_dismissed" {
  title           = "GitHub Repository Vulnerability Alert Dismissed"
  description     = "Detect when a repository vulnerability alert was dismissed, potentially ignoring critical security risks that may expose the repository to exploitation."
  severity        = "high"
  query           = query.repository_vulnerability_alert_dismissed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0010:T1567, TA0005:T1203, TA0005:T1190"
  })
}

query "repository_vulnerability_alert_dismissed" {
  sql = <<-EOQ
    select
      ${local.repository_vulnerability_alert_dismissed_sql_columns}
    from
      github_audit_log
    where
      action = 'repository_vulnerability_alert.dismiss'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "organization_ownership_transferred" {
  title           = "Organization Ownership Transferred"
  description     = "Detect when an organization was transferred to a new owner, which may indicate a takeover attempt or unauthorized privilege escalation."
  severity        = "medium"
  query           = query.organization_ownership_transferred
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_ownership_transferred" {
  sql = <<-EOQ
    select
      ${local.organization_ip_allow_list_updated_sql_columns}
    from
      github_audit_log
    where
      action = 'org.transferred'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "repository_visibility_set_public" {
  title           = "Repository Visibility Set Public"
  description     = "Detect when a private repository's visibility was set to public, potentially exposing proprietary or sensitive code."
  severity        = "high"
  query           = query.repository_visibility_set_public
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0001:T1195.002"
  })
}

query "repository_visibility_set_public" {
  sql = <<-EOQ
    select
      ${local.repository_create_events_sql_columns}
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
}

detection "personal_access_token_created" {
  title           = "Personal Access Token Created"
  description     = "Detect when a GitHub personal access token (PAT) was created, potentially granting access to repositories, actions, or APIs."
  severity        = "medium"
  query           = query.personal_access_token_created
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
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
}

detection "user_promoted_to_admin" {
  title           = "User Promoted to Organization Admin"
  description     = "Detect when a GitHub user was granted organization admin privileges, potentially leading to unauthorized control over repositories and settings."
  severity        = "critical"
  query           = query.user_promoted_to_admin
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

query "user_promoted_to_admin" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action = 'org.add_member'
      and (additional_fields ->> 'role') = 'admin'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ
}

detection "user_authentication_failed" {
  title           = "User Authentication Failed"
  description     = "Detect when a user failed to authenticate, which may indicate unauthorized access attempts or credential stuffing attacks."
  severity        = "medium"
  query           = query.user_authentication_failed
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
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
}
