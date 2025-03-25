locals {
  organization_common_tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization"
    service = "GitHub/Organization"
  })
}

benchmark "organization_detections" {
  title       = "Organization Detections"
  description = "This detection benchmark contains recommendations related to GitHub organizations."
  type        = "detection"
  children = [
    detection.organization_application_installed,
    detection.organization_application_uninstalled,
    detection.organization_ip_allow_list_entry_updated,
    detection.organization_moderator_added,
    detection.organization_moderator_removed,
    detection.organization_ownership_transferred,
    detection.organization_two_factor_authentication_disabled,
    detection.organization_user_added,
    detection.organization_user_granted_owner_role,
    detection.organization_user_removed,
  ]

  tags = merge(local.organization_common_tags, {
    type = "Benchmark"
  })
}

detection "organization_two_factor_authentication_disabled" {
  title           = "Organization Two-Factor Authentication Disabled"
  description     = "Detect when two-factor authentication was disabled for a GitHub organization, potentially increasing the risk of unauthorized access."
  documentation   = file("./detections/docs/organization_two_factor_authentication_disabled.md")
  severity        = "high"
  query           = query.organization_two_factor_authentication_disabled
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_two_factor_authentication_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'org.disable_two_factor_requirement'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_ip_allow_list_entry_updated" {
  title           = "Organization IP Allow List Entry Updated"
  description     = "Detect when changes were made to an organization's IP allow list entry, potentially indicating unauthorized network access modifications or security policy bypasses."
  documentation   = file("./detections/docs/organization_ip_allow_list_entry_updated.md")
  severity        = "medium"
  query           = query.organization_ip_allow_list_entry_updated
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_ip_allow_list_entry_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action in (
        'ip_allow_list_entry.create',
        'ip_allow_list_entry.destroy',
        'ip_allow_list_entry.update'
      )
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_moderator_added" {
  title           = "Organization Moderator Added"
  description     = "Detect when a user was added as a moderator in an organization, potentially increasing their privileges."
  documentation   = file("./detections/docs/organization_moderator_added.md")
  severity        = "medium"
  query           = query.organization_moderator_added
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_moderator_added" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action = 'organization_moderators.add_user'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_moderator_removed" {
  title           = "Organization Moderator Removed"
  description     = "Detect when an organization's moderator was removed, potentially reducing oversight and security controls."
  documentation   = file("./detections/docs/organization_moderator_removed.md")
  severity        = "medium"
  query           = query.organization_moderator_removed
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_moderator_removed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action = 'organization_moderators.remove_user'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_user_added" {
  title           = "Organization User Added"
  description     = "Detect when a user was added to a GitHub organization, which may indicate a new access provision or a potential unauthorized account being added."
  documentation   = file("./detections/docs/organization_user_added.md")
  severity        = "medium"
  query           = query.organization_user_added
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "organization_user_added" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action = 'org.add_member'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_user_removed" {
  title           = "Organization User Removed"
  description     = "Detect when a user was removed from a GitHub organization, potentially indicating an access revocation or an unauthorized removal."
  documentation   = file("./detections/docs/organization_user_removed.md")
  severity        = "medium"
  query           = query.organization_user_removed
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "organization_user_removed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action = 'org.remove_member'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_application_installed" {
  title           = "Organization Application Installed"
  description     = "Detect when an application integration was installed in a GitHub organization, potentially introducing new permissions or external service access."
  documentation   = file("./detections/docs/organization_application_installed.md")
  severity        = "low"
  query           = query.organization_application_installed
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_application_installed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_integration}
    from
      github_audit_log
    where
      action = 'integration_installation.create'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_application_uninstalled" {
  title           = "Organization Application Uninstalled"
  description     = "Detect when an application integration was uninstalled from a GitHub organization, which may impact service dependencies or security controls."
  documentation   = file("./detections/docs/organization_application_uninstalled.md")
  severity        = "medium"
  query           = query.organization_application_uninstalled
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1098, TA0001:T1195.002"
  })
}

query "organization_application_uninstalled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_integration}
    from
      github_audit_log
    where
      action = 'integration_installation.delete'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_ownership_transferred" {
  title           = "Organization Ownership Transferred"
  description     = "Detect when an organization was transferred to a new owner, which may indicate a takeover attempt or unauthorized privilege escalation."
  documentation   = file("./detections/docs/organization_ownership_transferred.md")
  severity        = "high"
  query           = query.organization_ownership_transferred
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_ownership_transferred" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'org.transfer'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}

detection "organization_user_granted_owner_role" {
  title           = "Organization User Granted Owner Role"
  description     = "Detect when an organization's user was granted the owner role, potentially leading to unauthorized control over repositories and settings."
  documentation   = file("./detections/docs/organization_user_granted_owner_role.md")
  severity        = "high"
  query           = query.organization_user_granted_owner_role
  display_columns = local.detection_display_columns_organization

  tags = merge(local.organization_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

query "organization_user_granted_owner_role" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_user}
    from
      github_audit_log
    where
      action = 'org.update_member'
      and (additional_fields ->> 'permission') = 'admin'
    order by
      tp_timestamp desc;
  EOQ

  tags = local.organization_common_tags
}
