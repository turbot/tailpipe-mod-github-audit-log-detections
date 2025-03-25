dashboard "activity_dashboard" {
  title         = "Audit Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "GitHub/Organization"
  }

  container {

    # Analysis
    card {
      query = query.activity_dashboard_total_events
      width = 2
    }

  }

  container {

    chart {
      title = "Events by Organization"
      query = query.activity_dashboard_events_by_org
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Repositories"
      query = query.activity_dashboard_events_by_repository
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Actors (Excluding Bots)"
      query = query.activity_dashboard_events_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs"
      query = query.activity_dashboard_events_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Actions"
      query = query.activity_dashboard_events_by_action
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Secret Scanning Alerts"
      query = query.activity_dashboard_secret_scanning_alerts
      type  = "table"
      width = 6
    }
  }
}

# Query definitions

query "activity_dashboard_total_events" {
  title       = "Log Count"
  description = "Count the total audit log entries."

  sql = <<-EOQ
    select
      count(*) as "Total Events"
    from
      github_audit_log;
  EOQ

  tags = {
    folder = "Organization"
  }
}

query "activity_dashboard_events_by_org" {
  title       = "Events by Organization"
  description = "Count audit log entries grouped by organization."

  sql = <<-EOQ
    select
      org as "Organization",
      count(*) as "Events"
    from
      github_audit_log
    where
      org is not null
    group by
      org
    order by
      count(*) desc;
  EOQ

  tags = {
    folder = "Organization"
  }
}

query "activity_dashboard_events_by_repository" {
  title       = "Top 10 Repositories"
  description = "List the top 10 repositories by log count."

  sql = <<-EOQ
    select
      additional_fields ->> 'repo' as "Repository",
      count(*) as "Events"
    from
      github_audit_log
    where
      additional_fields ->> 'repo' is not null
    group by
      additional_fields ->> 'repo'
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Repository"
  }
}

query "activity_dashboard_events_by_actor" {
  title       = "Top 10 Actors (Excluding Bots)"
  description = "List the top 10 actors by frequency, excluding bot accounts."

  sql = <<-EOQ
    select
      actor as "Actor",
      count(*) as "Events"
    from
      github_audit_log
    where
      actor is not null
      and (additional_fields -> 'actor_is_bot') = false
    group by
      actor
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Organization"
  }
}

query "activity_dashboard_events_by_source_ip" {
  title       = "Top 10 Source IPs"
  description = "List the top 10 source IPs by frequency, excluding internal GitHub IPs."

  sql = <<-EOQ
    select
      tp_source_ip as "Source IP",
      count(*) as "Events"
    from
      github_audit_log
    where
      tp_source_ip is not null
      and tp_source_ip not like '%github.com'
    group by
      tp_source_ip
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Organization"
  }
}

query "activity_dashboard_events_by_action" {
  title       = "Top 10 Actions"
  description = "List the 10 most frequently recorded actions in the audit events."

  sql = <<-EOQ
    select
      action as "Action",
      count(*) as "Events"
    from
      github_audit_log
    group by
      action
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Organization"
  }
}

query "activity_dashboard_secret_scanning_alerts" {
  title       = "Top 10 Secret Scanning Alerts"
  description = "List the top 10 repositories with the most secret scanning alerts."

  sql = <<-EOQ
    select
      repo as "Repository",
      count(*) as "Alerts"
    from
      github_audit_log
    where
      action = 'secret_scanning_alert.create'
    group by
      repo
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Repository"
  }
}
