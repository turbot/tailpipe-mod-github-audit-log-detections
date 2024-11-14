locals {
  audit_logs_detect_failed_workflow_actions_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "org")

  audit_logs_detect_branch_protection_policy_overrides_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields ->> '$' ->> 'repo', '/commit/', additional_fields ->> '$' ->> 'after')")

  audit_logs_detect_branch_protection_disabled_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'))")

  audit_logs_detect_organization_authentication_method_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org, '/settings/authentication')")

  audit_logs_detect_organization_allowed_ip_list_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  audit_logs_detect_organization_application_integration_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  audit_logs_detect_organization_moderator_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', additional_fields::JSON ->> 'user')")

  audit_logs_detect_organization_user_access_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  detect_audit_logs_with_public_repository_create_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  audit_logs_detect_repository_archive_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  audit_logs_detect_repository_collaborator_updates_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  audit_logs_detect_repository_create_events_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  audit_logs_detect_repository_visibility_changes_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  audit_logs_detect_dismissed_repository_vulnerabilities_sql_columns = replace(local.common_dimensions_audit_logs_sql_columns, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'), '/security/dependabot/', json_extract_string(additional_fields, '$.alert_number'))")
}

detection_benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    detection.audit_logs_detect_branch_protection_disabled_updates,
    detection.audit_logs_detect_branch_protection_policy_overrides,
    detection.audit_logs_detect_dismissed_repository_vulnerabilities,
    detection.audit_logs_detect_failed_workflow_actions,
    detection.audit_logs_detect_organization_allowed_ip_list_updates,
    detection.audit_logs_detect_organization_application_integration_updates,
    detection.audit_logs_detect_organization_authentication_method_updates,
    detection.audit_logs_detect_organization_moderator_updates,
    detection.audit_logs_detect_organization_user_access_updates,
    detection.audit_logs_detect_public_repository_create_updates,
    detection.audit_logs_detect_repository_archive_updates,
    detection.audit_logs_detect_repository_collaborator_updates,
    detection.audit_logs_detect_repository_create_events,
    detection.audit_logs_detect_repository_visibility_changes,
  ]

  tags = merge(local.github_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections and queries
 */

detection "audit_logs_detect_failed_workflow_actions" {
  title       = "Detect Failed GitHub Actions"
  description = "Detect instances in audit logs where GitHub Actions workflows fail, potentially indicating unauthorized changes, misconfigurations, or compromised workflows."
  severity    = "high"
  query       = query.audit_logs_detect_failed_workflow_actions

  references = [
    "https://docs.github.com/en/actions/creating-actions/setting-exit-codes-for-actions#about-exit-codes",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_detect_failed_workflow_actions" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_failed_workflow_actions_sql_columns}
    from
      github_audit_log
    where
      action = 'workflows.completed_workflow_run'
    order by
      tp_timestamp desc;
  EOQ
}

detection "audit_logs_detect_branch_protection_policy_overrides" {
  title       = "Detect Branch Protection Policy Overrides"
  description = "Detect events in audit logs where branch protection policies are overridden, potentially allowing unauthorized changes, force pushes, or unverified commits."
  severity    = "high"
  query       = query.audit_logs_detect_branch_protection_policy_overrides

  references = [
    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "audit_logs_detect_branch_protection_policy_overrides" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_branch_protection_policy_overrides_sql_columns}
    from
      github_audit_log
    where
      action = 'protected_branch.policy_override'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_branch_protection_disabled_updates" {
  title       = "Detect Disabling of Branch Protection Rules"
  description = "Detect actions where branch protection rules are overridden or disabled, potentially exposing the repository to unauthorized changes or malicious commits."
  severity    = "high"
  query       = query.audit_logs_detect_branch_protection_disabled_updates

  references = [
    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "audit_logs_detect_branch_protection_disabled_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_branch_protection_disabled_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'protected_branch.destroy'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_organization_authentication_method_updates" {
  title       = "Detect Organization Authentication Method Updates"
  description = "Detect actions where the organization's authentication methods are updated, potentially indicating changes that could weaken security controls or allow unauthorized access."
  severity    = "critical"
  query       = query.audit_logs_detect_organization_authentication_method_updates

  references = [
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "audit_logs_detect_organization_authentication_method_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_organization_authentication_method_updates_sql_columns}
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

detection "audit_logs_detect_organization_allowed_ip_list_updates" {
  title       = "Detect Organization IP Allow List Updates"
  description = "Detect actions where updates are made to the organization's allowed IP list, which may indicate unauthorized network access changes or potential IP-based access bypasses."
  severity    = "medium"
  query       = query.audit_logs_detect_organization_allowed_ip_list_updates

  references = [
    "https://docs.github.com/en/apps/maintaining-github-apps/managing-allowed-ip-addresses-for-a-github-app",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "audit_logs_detect_organization_allowed_ip_list_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_organization_allowed_ip_list_updates_sql_columns}
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
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_organization_moderator_updates" {
  title       = "Detect Organization Moderator List Updates"
  description = "Detect actions where updates are made to the organization's moderator list, which may indicate changes to privileged roles within the organization."
  severity    = "medium"
  query       = query.audit_logs_detect_organization_moderator_updates

  references = [
    "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-moderators-in-your-organization",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_detect_organization_moderator_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_organization_moderator_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'organization_moderators.add_user'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_organization_user_access_updates" {
  title       = "Detect Adding or Removing Users from Organization"
  description = "Detect actions where users are added to or removed from the organization, which may indicate changes in access control or potential insider threats."
  severity    = "low"
  query       = query.audit_logs_detect_organization_user_access_updates

  references = [
    "https://docs.github.com/en/organizations/managing-membership-in-your-organization",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "audit_logs_detect_organization_user_access_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_organization_user_access_updates_sql_columns}
    from
      github_audit_log
    where
      action in (
    'org.add_member',
    'org.remove_member'
    )
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_organization_application_integration_updates" {
  title       = "Detect Adding Application Integrations to an Organization"
  description = "Detect actions where an application integration is added to the organization, potentially introducing new permissions or access to external services."
  severity    = "low"
  query       = query.audit_logs_detect_organization_application_integration_updates

  references = [
    "https://docs.github.com/en/organizations/managing-membership-in-your-organization",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_detect_organization_application_integration_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_organization_application_integration_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'integration_installation.create'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_public_repository_create_updates" {
  title       = "Detect Public Repository Create Events"
  description = "Detect actions where a repository's visibility was set to public, potentially exposing sensitive code or data to unauthorized users."
  severity    = "medium"
  query       = query.detect_audit_logs_with_public_repository_create

  references = [
    "https://docs.github.com/en/get-started/quickstart/create-a-repo",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "detect_audit_logs_with_public_repository_create" {
  sql = <<-EOQ
    select
      ${local.detect_audit_logs_with_public_repository_create_sql_columns}
    from
      github_audit_log
    where
      action = 'repo.create'
      and json_extract(additional_fields, '$.public_repo') = 'true'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_repository_archive_updates" {
  title       = "Detect Repository Archives"
  description = "Detect actions where a repository was archived, potentially impacting repository accessibility and signaling a deprecation or maintenance decision."
  severity    = "low"
  query       = query.audit_logs_detect_repository_archive_updates

  references = [
    "https://docs.github.com/en/get-started/quickstart/create-a-repo",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_detect_repository_archive_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_repository_archive_updates_sql_columns}
    from
      github_audit_log
    where
      action = 'repo.archived'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_repository_collaborator_updates" {
  title       = "Detect Repository Collaborator Updates"
  description = "Detect actions where the repository collaborator list was modified, indicating potential changes in access permissions or security policies within the repository."
  severity    = "medium"
  query       = query.audit_logs_detect_repository_collaborator_updates

  references = [
    "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/managing-an-individuals-access-to-an-organization-repository",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "audit_logs_detect_repository_collaborator_updates" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_repository_collaborator_updates_sql_columns}
    from
      github_audit_log
    where
      action in ('repo.add_member', 'repo.remove_member')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_repository_create_events" {
  title       = "Detect Repository Create Events"
  description = "Detect actions where a new repository was created, potentially introducing new resources or entry points that may require monitoring for security compliance."
  severity    = "low"
  query       = query.audit_logs_detect_repository_create_events

  references = [
    "https://docs.github.com/en/get-started/quickstart/create-a-repo",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_detect_repository_create_events" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_repository_create_events_sql_columns}
    from
      github_audit_log
    where
      action = 'repo.create'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_repository_visibility_changes" {
  title       = "Detect Repository Visibility Changes"
  description = "Detect actions where a repository's visibility was changed to either public or private, which may expose sensitive data or restrict necessary access."
  severity    = "high"
  query       = query.audit_logs_detect_repository_visibility_changes

  references = [
    "https://docs.github.com/en/get-started/quickstart/create-a-repo",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "audit_logs_detect_repository_visibility_changes" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_repository_visibility_changes_sql_columns}
    from
      github_audit_log
    where
      action in ('repo.access')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_detect_dismissed_repository_vulnerabilities" {
  title       = "Detect Repository Vulnerability Dismissed Events"
  description = "Detect actions where a repository vulnerability was dismissed, potentially ignoring critical security risks that may expose the repository to exploitation."
  severity    = "high"
  query       = query.audit_logs_detect_dismissed_repository_vulnerabilities

  references = []

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "audit_logs_detect_dismissed_repository_vulnerabilities" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_dismissed_repository_vulnerabilities_sql_columns}
    from
      github_audit_log
    where
      action in ('repository_vulnerability_alert.dismiss')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

