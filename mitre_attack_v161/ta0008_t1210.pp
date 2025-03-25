locals {
  mitre_attack_v161_ta0008_t1210_common_tags = merge(local.mitre_attack_v161_ta0008_common_tags, {
    mitre_attack_technique_id = "T1210"
  })
}

benchmark "mitre_attack_v161_ta0008_t1210" {
  title         = "T1210 Exploitation of Remote Services"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008_t1210.md")
  children = [
    detection.repository_visibility_set_public,
  ]

  tags = local.mitre_attack_v161_ta0008_t1210_common_tags
}

