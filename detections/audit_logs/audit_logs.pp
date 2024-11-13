// TODO: Verify the resource column for the queries

locals {
  audit_logs_action_failed_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "org")

  audit_logs_branch_protection_policy_override_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'), '/commit/', json_extract_string(additional_fields, '$.after'))")

  audit_logs_branch_protection_disabled_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'))")

  audit_logs_organization_authentication_method_update_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org, '/settings/authentication')")

  audit_logs_organization_ip_allow_list_modified_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  audit_logs_organization_add_application_integration_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  audit_logs_organization_add_user_org_moderator_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  audit_logs_organization_add_remove_user_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/orgs/', org)")

  detect_audit_logs_with_public_repository_create_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  detect_audit_logs_with_repository_archive_events_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  detect_audit_logs_with_repository_collaborator_update_events_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  detect_audit_logs_with_repository_create_events_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  detect_audit_logs_with_repository_visibility_change_events_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', additional_fields::JSON ->> 'repo')")

  detect_audit_logs_with_repository_vulnerability_dismissed_events_sql = replace(local.common_dimensions_audit_logs_sql, "__RESOURCE_SQL__", "CONCAT('https://github.com/', json_extract_string(additional_fields, '$.repo'), '/security/dependabot/', json_extract_string(additional_fields, '$.alert_number'))")
}

detection_benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    detection.audit_logs_action_failed,
    detection.audit_logs_branch_protection_policy_override,
    detection.audit_logs_branch_protection_disabled,
    detection.audit_logs_organization_authentication_method_update,
    detection.audit_logs_organization_ip_allow_list_modified,
    detection.audit_logs_organization_add_user_org_moderator,
    detection.audit_logs_organization_add_remove_user,
    detection.audit_logs_organization_add_application_integration,
    detection.detect_audit_logs_with_public_repository_create_events,
    detection.detect_audit_logs_with_repository_archive_events,
    detection.detect_audit_logs_with_repository_collaborator_update_events,
    detection.detect_audit_logs_with_repository_create_events,
    # detection.detect_audit_logs_with_initial_private_repo_access,
    detection.detect_audit_logs_with_repository_visibility_change_events,
    detection.detect_audit_logs_with_repository_vulnerability_dismissed_events,
  ]

  tags = merge(local.github_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections and queries
 */

detection "audit_logs_action_failed" {
  title       = "Detect Failed GitHub Actions in Audit Logs"
  description = "Detect GitHub action failures in audit logs."
  severity    = "high"
  query       = query.audit_logs_action_failed

  references = [
    "https://docs.github.com/en/actions/creating-actions/setting-exit-codes-for-actions#about-exit-codes",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_action_failed" {
  sql = <<-EOQ
    select
      ${local.audit_logs_action_failed_sql}
    from
      github_audit_log
    where
      action = 'workflows.completed_workflow_run'
    order by
      tp_timestamp desc;
  EOQ
}

detection "audit_logs_branch_protection_policy_override" {
  title       = "Detect GitHub Branch Protection Policy Overrides in Audit Logs"
  description = "Detect GitHub branch protection policy overrides in audit logs."
  severity    = "high"
  query       = query.audit_logs_branch_protection_policy_override

  references = [
    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "audit_logs_branch_protection_policy_override" {
  sql = <<-EOQ
    select
      ${local.audit_logs_branch_protection_policy_override_sql}
    from
      github_audit_log
    where
      action = 'protected_branch.policy_override'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_branch_protection_disabled" {
  title       = "Detect Disabling of GitHub Branch Protection Rules in Audit Logs"
  description = "Identifies actions in GitHub audit logs where branch protection rules are overridden or disabled, which may indicate unauthorized or risky modifications to repository protections."
  severity    = "high"
  query       = query.audit_logs_branch_protection_disabled

  references = [
    "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "audit_logs_branch_protection_disabled" {
  sql = <<-EOQ
    select
      ${local.audit_logs_branch_protection_disabled_sql}
    from
      github_audit_log
    where
      action = 'protected_branch.destroy'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_organization_authentication_method_update" {
  title       = "Detect Changes to GitHub Organization Authentication in Audit Logs"
  description = "Identifies actions in GitHub audit logs where updates are made to the GitHub organization's authentication methods."
  severity    = "critical"
  query       = query.audit_logs_organization_authentication_method_update

  references = [
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "audit_logs_organization_authentication_method_update" {
  sql = <<-EOQ
    select
      ${local.audit_logs_organization_authentication_method_update_sql}
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

detection "audit_logs_organization_ip_allow_list_modified" {
  title       = "Detect Changes to GitHub Organization IP Allow List in Audit Logs"
  description = "Identifies actions in GitHub audit logs where updates are made to the GitHub organization's allowed IP list."
  severity    = "medium"
  query       = query.audit_logs_organization_ip_allow_list_modified

  references = [
    "https://docs.github.com/en/apps/maintaining-github-apps/managing-allowed-ip-addresses-for-a-github-app",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "audit_logs_organization_ip_allow_list_modified" {
  sql = <<-EOQ
    select
      ${local.audit_logs_organization_ip_allow_list_modified_sql}
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

detection "audit_logs_organization_add_user_org_moderator" {
  title       = "Detect Changes to GitHub Organization Moderator User List in Audit Logs"
  description = "Identifies actions in GitHub audit logs where updates are made to the GitHub organization's org moderator list."
  severity    = "medium"
  query       = query.audit_logs_organization_add_user_org_moderator

  references = [
    "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-moderators-in-your-organization",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_organization_add_user_org_moderator" {
  sql = <<-EOQ
    select
      ${local.audit_logs_organization_add_user_org_moderator_sql}
    from
      github_audit_log
    where
      action = 'organization_moderators.add_user'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "audit_logs_organization_add_remove_user" {
  title       = "Detect Adding or Removing User from Organization in Audit Logs"
  description = "Identifies actions in GitHub audit logs where users are either added or removed."
  severity    = "low"
  query       = query.audit_logs_organization_add_remove_user

  references = [
    "https://docs.github.com/en/organizations/managing-membership-in-your-organization",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "audit_logs_organization_add_remove_user" {
  sql = <<-EOQ
    select
      ${local.audit_logs_organization_add_remove_user_sql}
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

detection "audit_logs_organization_add_application_integration" {
  title       = "Detect Adding an Application Integration to an Organization in Audit Logs"
  description = "Identifies actions in GitHub audit logs where an application integration is added."
  severity    = "low"
  query       = query.audit_logs_organization_add_application_integration

  references = [
    "https://docs.github.com/en/organizations/managing-membership-in-your-organization",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_logs_organization_add_application_integration" {
  sql = <<-EOQ
    select
      ${local.audit_logs_organization_add_application_integration_sql}
    from
      github_audit_log
    where
      action = 'integration_installation.create'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "detect_audit_logs_with_public_repository_create_events" {
  title       = "Detect Audit Logs with Public Repository Create Events"
  description = "Identifies actions in GitHub audit logs where a repository was made public."
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
      ${local.detect_audit_logs_with_public_repository_create_sql}
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

detection "detect_audit_logs_with_repository_archive_events" {
  title       = "Detect Audit Logs with Repository Archive Events"
  description = "Identifies actions in GitHub audit logs where a repository was archived."
  severity    = "low"
  query       = query.detect_audit_logs_with_repository_archive_events

  references = [
    "https://docs.github.com/en/get-started/quickstart/create-a-repo",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "detect_audit_logs_with_repository_archive_events" {
  sql = <<-EOQ
    select
      ${local.detect_audit_logs_with_repository_archive_events_sql}
    from
      github_audit_log
    where
      action = 'repo.archived'
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "detect_audit_logs_with_repository_collaborator_update_events" {
  title       = "Detect Audit Logs with Repository Collaborator Update Events"
  description = "Identifies actions in GitHub audit logs where a repository collaborator list was updated."
  severity    = "medium"
  query       = query.detect_audit_logs_with_repository_collaborator_update_events

  references = [
    "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/managing-an-individuals-access-to-an-organization-repository",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "detect_audit_logs_with_repository_collaborator_update_events" {
  sql = <<-EOQ
    select
      ${local.detect_audit_logs_with_repository_collaborator_update_events_sql}
    from
      github_audit_log
    where
      action in ('repo.add_member', 'repo.remove_member')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "detect_audit_logs_with_repository_create_events" {
  title       = "Detect Audit Logs with Repository Create Events"
  description = "Identifies actions in GitHub audit logs where a repository was created."
  severity    = "low"
  query       = query.detect_audit_logs_with_repository_create_events

  references = [
    "https://docs.github.com/en/get-started/quickstart/create-a-repo",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = ""
  })
}

query "detect_audit_logs_with_repository_create_events" {
  sql = <<-EOQ
    select
      ${local.detect_audit_logs_with_repository_create_events_sql}
    from
      github_audit_log
    where
      action in ('repo.add_member', 'repo.remove_member')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

# detection "detect_audit_logs_with_initial_private_repo_access" {
#   title       = "Detect Audit Logs with Initial Repo Access"
#   description = "Identifies actions in GitHub audit logs where a private repository was accessed for the first time by a user"
#   severity    = "low"
#   query       = query.detect_audit_logs_with_initial_private_repo_access

#   references = [
#     "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/managing-an-individuals-access-to-an-organizat",
#   ]

#   tags = merge(local.github_common_tags, {
#     mitre_attack_ids = ""
#   })
# }

# query "detect_audit_logs_with_initial_private_repo_access" {
#   sql = <<-EOQ
#     select
#       ${local.detect_audit_logs_with_repository_create_events_sql}
#     from
#       github_audit_log
#     where
#       action in ('repo.add_member', 'repo.remove_member')
#     order by
#       tp_timestamp desc
#     limit 20;
#   EOQ
# }


detection "detect_audit_logs_with_repository_visibility_change_events" {
  title       = "Detect Audit Logs with Repository Visibility Change Events"
  description = "Identifies actions in GitHub audit logs where a repository was either made public or private."
  severity    = "high"
  query       = query.detect_audit_logs_with_repository_visibility_change_events

  references = [
    "https://docs.github.com/en/get-started/quickstart/create-a-repo",
  ]

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "detect_audit_logs_with_repository_visibility_change_events" {
  sql = <<-EOQ
    select
      ${local.detect_audit_logs_with_repository_visibility_change_events_sql}
    from
      github_audit_log
    where
      action in ('repo.access')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

detection "detect_audit_logs_with_repository_vulnerability_dismissed_events" {
  title       = "Detect Audit Logs with Repository Vulnerability Dismissed Events"
  description = "Identifies actions in GitHub audit logs where a repository vulnerability was dismissed."
  severity    = "high"
  query       = query.detect_audit_logs_with_repository_vulnerability_dismissed_events

  references = []

  tags = merge(local.github_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "detect_audit_logs_with_repository_vulnerability_dismissed_events" {
  sql = <<-EOQ
    select
      ${local.detect_audit_logs_with_repository_vulnerability_dismissed_events_sql}
    from
      github_audit_log
    where
      action in ('repository_vulnerability_alert.dismiss')
    order by
      tp_timestamp desc
    limit 20;
  EOQ
}

