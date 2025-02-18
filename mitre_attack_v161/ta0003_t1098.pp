locals {
  mitre_attack_v161_ta0003_t1098_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_attack_technique_id = "T1098"
  })
}

benchmark "mitre_attack_v161_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098.md")
  children = [
    benchmark.mitre_attack_v161_ta0003_t1098_001,
    benchmark.mitre_attack_v161_ta0003_t1098_003,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1098_001" {
  title         = "T1098.001 Account Manipulation: Additional Cloud Credentials"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098_001.md")
  children = [
    detection.organization_oauth_application_authorized,
    detection.organization_oauth_application_revoked,
    detection.personal_access_token_created,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1098_003" {
  title         = "T1098.003 Account Manipulation: Additional Cloud Roles"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098_003.md")
  children = [
    detection.user_promoted_to_admin,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}
