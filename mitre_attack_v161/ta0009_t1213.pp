locals {
  mitre_attack_v161_ta0009_t1213_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_attack_technique_id = "T1213"
  })
}

benchmark "mitre_attack_v161_ta0009_t1213" {
  title         = "T1213 Data from Information Repositories"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1213.md")
  children = [
    detection.organization_oauth_application_authorized,
    detection.personal_access_token_created,
    detection.repository_visibility_set_public,
  ]

  tags = local.mitre_attack_v161_ta0009_t1213_common_tags
}
