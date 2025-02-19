locals {
  mitre_attack_v161_ta0003_t1136_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_attack_technique_id = "T1136"
  })
}

benchmark "mitre_attack_v161_ta0003_t1136" {
  title         = "T1136 Create Account"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1136.md")
  children = [
    benchmark.mitre_attack_v161_ta0003_t1136_003,
  ]

  tags = local.mitre_attack_v161_ta0003_t1136_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1136_003" {
  title         = "T1136.003 Create Account: Cloud Account"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1136_003.md")
  children = [
    detection.organization_moderator_added,
    detection.organization_user_added,
    detection.repository_collaborator_list_updated,
  ]

  tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_attack_technique_id = "T1136.003"
  })
}
