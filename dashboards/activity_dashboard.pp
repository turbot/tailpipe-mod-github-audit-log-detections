dashboard "github_activity_dashboard" {
  title         = "GitHub Audit Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "GitHub/AuditLog"
  }

  container {

    # Analysis
    card {
      query = query.github_activity_dashboard_total_logs
      width = 2
    }

  }

  container {

    chart {
      title = "Logs by Organization"
      query = query.github_activity_dashboard_logs_by_org
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Repository"
      query = query.github_activity_dashboard_logs_by_repository
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Actors (Excluding Bots)"
      query = query.github_activity_dashboard_logs_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs"
      query = query.github_activity_dashboard_logs_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Actions"
      query = query.github_activity_dashboard_logs_by_action
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Actions"
      query = query.github_activity_dashboard_failed_logins
      type  = "table"
      width = 6
    }
  }

}

# Query definitions

query "github_activity_dashboard_total_logs" {
  title = "Log Count"

  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      github_audit_log;
  EOQ
}

query "github_activity_dashboard_logs_by_org" {
  title = "Logs by Organization"

  sql = <<-EOQ
    select
      org as "Organization",
      count(*) as "Logs"
    from
      github_audit_log
    where
      org is not null
    group by
      org
    order by
      count(*) desc;
  EOQ
}

query "github_activity_dashboard_logs_by_repository" {
  title = "Logs by Repository"

  sql = <<-EOQ
    select
      additional_fields ->> 'repo' as "Repository",
      count(*) as "Logs"
    from
      github_audit_log
    where
      additional_fields ->> 'repo' is not null
    group by
      additional_fields ->> 'repo'
    order by
      count(*) desc;
  EOQ
}

query "github_activity_dashboard_logs_by_actor" {
  title = "Top 10 Actors (Excluding Bots)"

  sql = <<-EOQ
    select
      actor as "Actor",
      count(*) as "Logs"
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
}

query "github_activity_dashboard_logs_by_source_ip" {
  title = "Top 10 Source IPs"

  sql = <<-EOQ
    select
      tp_source_ip as "Source IP",
      count(*) as "Logs"
    from
      github_audit_log
    where
      tp_source_ip is not null
      and tp_source_ip not like '%github.com'
      and tp_source_ip != 'GitHub Internal'
    group by
      tp_source_ip
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "github_activity_dashboard_logs_by_action" {
  title = "Top 10 Actions"

  sql = <<-EOQ
    select
      action as "Action",
      count(*) as "Logs"
    from
      github_audit_log
    group by
      action
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "github_activity_dashboard_failed_logins" {
  title = "Top 10 Failed User Logins"

  sql = <<-EOQ
    select
      actor as "User",
      count(*) as "Failed Attempts"
    from
      github_audit_log
    where
      action = 'user.failed_login'
      and actor is not null
    group by
      actor
    order by
      count(*) desc
    limit 10;
  EOQ
}

