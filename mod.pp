mod "github_audit_log_detections" {
  # hub metadata
  title         = "GitHub Audit Log Detections"
  description   = "Run detections and view dashboards for your GitHub audit logs to monitor and analyze activity across your GitHub organizations and repositories using Powerpipe and Tailpipe."
  color         = "#191717"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/github-audit-log-detections.svg"
  categories    = ["dashboard", "detections", "github"]
  database      = var.database

  opengraph {
    title       = "Powerpipe Mod for GitHub Audit Log Detections"
    description = "Run detections and view dashboards for your GitHub audit logs to monitor and analyze activity across your GitHub organizations and repositories Powerpipe and Tailpipe."
    image       = "/images/mods/turbot/github-audit-log-detections-social-graphic.png"
  }
}
