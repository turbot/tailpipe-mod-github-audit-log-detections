locals {
  mitre_attack_v161_ta0010_t1484_common_tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    mitre_attack_technique_id = "t1484"
  })
}

benchmark "mitre_attack_v161_ta0010_t1484" {
  title         = "T1484 	Domain or Tenant Policy Modification"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1484.md")
  children = [
    detection.organization_ip_allow_list_entry_updated,
    detection.organization_two_factor_authentication_disabled,
  ]

  tags = local.mitre_attack_v161_ta0010_t1484_common_tags
}
