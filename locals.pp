// Benchmarks and controls for specific services should override the "service" tag
locals {
  github_common_tags = {
    category = "Security"
    plugin   = "github"
    service  = "GitHub"
  }
}