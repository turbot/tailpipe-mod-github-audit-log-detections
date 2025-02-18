locals {
  mitre_attack_v161_ta0009_t1119_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_attack_technique_id = "T1119"
  })
}

benchmark "mitre_attack_v161_ta0009_t1119" {
  title         = "T1119 Automated Collection"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1119.md")
  children = [
    detection.personal_access_token_created,
    detection.organization_oauth_application_authorized,
  ]

  tags = local.mitre_attack_v161_ta0009_t1119_common_tags
}
