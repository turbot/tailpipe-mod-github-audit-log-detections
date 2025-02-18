locals {
  mitre_attack_v161_ta0001_t1199_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_attack_technique_id = "T1199"
  })
}

benchmark "mitre_attack_v161_ta0001_t1199" {
  title = "T1199 Trusted Relationship"
  type  = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1199.md")
  children = [
    detection.organization_application_installed,
    detection.organization_oauth_application_authorized,
    detection.organization_oauth_application_revoked,
    detection.repository_collaborator_updates,
  ]

  tags = local.mitre_attack_v161_ta0001_t1199_common_tags
}
