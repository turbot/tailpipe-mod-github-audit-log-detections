locals {
  mitre_attack_v161_ta0001_t1078_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_attack_technique_id = "T1078"
  })
}

benchmark "mitre_attack_v161_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1078.md")
  children = [
    benchmark.mitre_attack_v161_ta0001_t1078_001,
    benchmark.mitre_attack_v161_ta0001_t1078_004,
  ]

  tags = local.mitre_attack_v161_ta0001_t1078_common_tags
}

benchmark "mitre_attack_v161_ta0001_t1078_001" {
  title         = "T1078.001 Valid Accounts: Default Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1078_001.md")
  children = [
    detection.organization_application_installed,
    detection.organization_moderator_added,
    detection.organization_user_added,
    detection.personal_access_token_created,

  ]

  tags = merge(local.mitre_attack_v161_ta0001_t1078_common_tags, {
    mitre_attack_technique_id = "T1078.001"
  })
}

benchmark "mitre_attack_v161_ta0001_t1078_004" {
  title         = "T1078.004 Valid Accounts: Cloud Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1078_004.md")
  children = [
    detection.organization_oauth_application_authorized,
    detection.organization_oauth_application_revoked,
    detection.organization_two_factor_authentication_disabled,
    detection.personal_access_token_created,
  ]

  tags = merge(local.mitre_attack_v161_ta0001_t1078_common_tags, {
    mitre_attack_technique_id = "T1078.004"
  })
}