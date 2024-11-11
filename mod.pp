mod "github" {
  # hub metadata
  title         = "GitHub"
  description   = "Search your GitHub audit logs for high risk actions using Tailpipe."
  color         = "#191717"
  #documentation = file("./docs/index.md")
  #icon          = "/images/mods/turbot/github.svg"
  categories    = ["github", "security"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for GitHub"
    description = "Search your GitHub audit logs for high risk actions using Tailpipe."
    #image       = "/images/mods/turbot/github-social-graphic.png"
  }
}
