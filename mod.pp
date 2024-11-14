mod "github_detections" {
  # hub metadata
  title         = "GitHub Detections"
  description   = "Search your GitHub audit logs for high risk actions using Tailpipe."
  color         = "#191717"
  #documentation = file("./docs/index.md")
  #icon          = "/images/mods/turbot/github.svg"
  categories    = ["github", "security"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for GitHub Detections"
    description = "Search your GitHub audit logs for high risk actions using Tailpipe."
    #image       = "/images/mods/turbot/github-social-graphic.png"
  }
}
