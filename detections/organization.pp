benchmark "organization_detections" {
  title       = "Organization Detections"
  description = "This detection benchmark contains recommendations related to GitHub organizations."
  type        = "detection"
  children = [
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
    detection.organization_user_granted_admin_privilege,
    detection.organization_user_removed,
  ]

  tags = merge(local.github_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}

detection "organization_saml_disabled" {
  title           = "Organization SAML Disabled"
  description     = "Detect when SAML authentication was disabled for a GitHub organization, potentially allowing unauthorized access or weakening authentication controls."
  documentation   = file("./detections/docs/organization_saml_disabled.md")
  severity        = "high"
  query           = query.organization_saml_disabled
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_saml_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization_authentication}
    from
      github_audit_log
    where
      action = 'org.saml_disabled'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_two_factor_authentication_disabled" {
  title           = "Organization Two-Factor Authentication Disabled"
  description     = "Detect when two-factor authentication was disabled for a GitHub organization, potentially increasing the risk of unauthorized access."
  documentation   = file("./detections/docs/organization_two_factor_authentication_disabled.md")
  severity        = "high"
  query           = query.organization_two_factor_authentication_disabled
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_two_factor_authentication_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization_authentication}
    from
      github_audit_log
    where
      action = 'org.disable_two_factor_requirement'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_ip_allow_list_updated" {
  title           = "Organization IP Allow List Updated"
  description     = "Detect when changes were made to an organization's IP allow list, potentially indicating unauthorized network access modifications or security policy bypasses."
  documentation   = file("./detections/docs/organization_ip_allow_list_updated.md")
  severity        = "medium"
  query           = query.organization_ip_allow_list_updated
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_ip_allow_list_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
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

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_moderator_added" {
  title           = "Organization Moderator Added"
  description     = "Detect when a user was added as a moderator in an organization, potentially increasing their privileges."
  documentation   = file("./detections/docs/organization_moderator_added.md")
  severity        = "medium"
  query           = query.organization_moderator_added
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_moderator_added" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization_user}
    from
      github_audit_log
    where
      action = 'organization_moderators.add_user'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_moderator_removed" {
  title           = "Organization Moderator Removed"
  description     = "Detect when an organization's moderator was removed, potentially reducing oversight and security controls."
  documentation   = file("./detections/docs/organization_moderator_removed.md")
  severity        = "high"
  query           = query.organization_moderator_removed
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_moderator_removed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization_user}
    from
      github_audit_log
    where
      action = 'organization_moderators.remove_user'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_user_added" {
  title           = "Organization User Added"
  description     = "Detect when a user was added to a GitHub organization, which may indicate a new access provision or a potential unauthorized account being added."
  documentation   = file("./detections/docs/organization_user_added.md")
  severity        = "low"
  query           = query.organization_user_added
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "organization_user_added" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'org.add_member'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_user_removed" {
  title           = "Organization User Removed"
  description     = "Detect when a user was removed from a GitHub organization, potentially indicating an access revocation or an unauthorized removal."
  documentation   = file("./detections/docs/organization_user_removed.md")
  severity        = "medium"
  query           = query.organization_user_removed
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "organization_user_removed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'org.remove_member'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_application_installed" {
  title           = "Organization Application Installed"
  description     = "Detect when an application integration was installed in a GitHub organization, potentially introducing new permissions or external service access."
  documentation   = file("./detections/docs/organization_application_installed.md")
  severity        = "low"
  query           = query.organization_application_installed
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_application_installed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'integration_installation.create'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_application_removed" {
  title           = "Organization Application Removed"
  description     = "Detect when an application integration was removed from a GitHub organization, which may impact service dependencies or security controls."
  documentation   = file("./detections/docs/organization_application_removed.md")
  severity        = "medium"
  query           = query.organization_application_removed
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098, TA0001:T1195.002"
  })
}

query "organization_application_removed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'integration_installation.delete'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_oauth_application_authorized" {
  title           = "Organization OAuth Application Authorized"
  description     = "Detect when an OAuth application was authorized in a GitHub organization, potentially granting external services access to organization data."
  documentation   = file("./detections/docs/organization_oauth_application_authorized.md")
  severity        = "low"
  query           = query.organization_oauth_application_authorized
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "organization_oauth_application_authorized" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'oauth_application.authorize'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_oauth_application_revoked" {
  title           = "Organization OAuth Application Revoked"
  description     = "Detect when an OAuth application authorization was revoked in a GitHub organization, which may indicate security control enforcement or a misconfiguration."
  documentation   = file("./detections/docs/organization_oauth_application_revoked.md")
  severity        = "medium"
  query           = query.organization_oauth_application_revoked
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1098, TA0001:T1195.002"
  })
}

query "organization_oauth_application_revoked" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_organization}
    from
      github_audit_log
    where
      action = 'oauth_application.revoke'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_ownership_transferred" {
  title           = "Organization Ownership Transferred"
  description     = "Detect when an organization was transferred to a new owner, which may indicate a takeover attempt or unauthorized privilege escalation."
  documentation   = file("./detections/docs/organization_ownership_transferred.md")
  severity        = "medium"
  query           = query.organization_ownership_transferred
  display_columns = local.audit_log_organization_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
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
      action = 'org.transferred'
      and (additional_fields -> 'actor_is_bot') = false
    order by
      tp_timestamp desc;
  EOQ

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}

detection "organization_user_granted_admin_privilege" {
  title           = "Organization User Granted Admin Privilege"
  description     = "Detect when an organization's user was granted admin privileges, potentially leading to unauthorized control over repositories and settings."
  documentation   = file("./detections/docs/organization_user_granted_admin_privilege.md")
  severity        = "high"
  query           = query.organization_user_granted_admin_privilege
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder           = "Organization",
    service          = "GitHub/Organization",
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

query "organization_user_granted_admin_privilege" {
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

  tags = merge(local.github_audit_log_detections_common_tags, {
    folder  = "Organization",
    service = "GitHub/Organization"
  })
}