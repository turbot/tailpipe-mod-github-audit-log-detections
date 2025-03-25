locals {
  mitre_attack_v161_ta0040_t1485_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1485"
  })
}

benchmark "mitre_attack_v161_ta0040_t1485" {
  title         = "T1485 Data Destruction"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1485.md")
  children = [
    detection.repository_archived,
  ]

  tags = local.mitre_attack_v161_ta0040_t1485_common_tags
}
