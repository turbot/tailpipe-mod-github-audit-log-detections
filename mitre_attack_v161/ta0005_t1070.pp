locals {
  mitre_attack_v161_ta0005_t1070_common_tags = merge(local.mitre_attack_v161_ta0005_common_tags, {
    mitre_attack_technique_id = "T1070"
  })
}

benchmark "mitre_attack_v161_ta0005_t1070" {
  title         = "T1070 Indicator Removal"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1070.md")
  children = [
    detection.repository_vulnerability_alert_dismissed,
  ]

  tags = local.mitre_attack_v161_ta0005_t1070_common_tags
}

