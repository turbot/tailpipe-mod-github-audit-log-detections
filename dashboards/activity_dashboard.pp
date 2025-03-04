dashboard "activity_dashboard" {
  title         = "Audit Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "GitHub/AuditLog"
  }

  container {

    # Analysis
    card {
      query = query.activity_dashboard_total_logs
      width = 2
    }

  }

  container {

    chart {
      title = "Logs by Organization"
      query = query.activity_dashboard_logs_by_org
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Repository"
      query = query.activity_dashboard_logs_by_repository
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Actors (Excluding Bots)"
      query = query.activity_dashboard_logs_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs"
      query = query.activity_dashboard_logs_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Actions"
      query = query.activity_dashboard_logs_by_action
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Failed User Logins"
      query = query.activity_dashboard_failed_logins
      type  = "table"
      width = 6
    }
  }
}

# Query definitions

query "activity_dashboard_total_logs" {
  title       = "Log Count"
  description = "Count the total audit log entries."

  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      github_audit_log;
  EOQ
}

query "activity_dashboard_logs_by_org" {
  title       = "Logs by Organization"
  description = "Count audit log entries grouped by organization."

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

query "activity_dashboard_logs_by_repository" {
  title       = "Logs by Repository"
  description = "Count audit log entries grouped by repository."

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

query "activity_dashboard_logs_by_actor" {
  title       = "Top 10 Actors (Excluding Bots)"
  description = "List the top 10 actors by frequency, excluding bot accounts."

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

query "activity_dashboard_logs_by_source_ip" {
  title       = "Top 10 Source IPs"
  description = "List the top 10 source IPs by frequency, excluding internal GitHub IPs."

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

query "activity_dashboard_logs_by_action" {
  title       = "Top 10 Actions"
  description = "List the 10 most frequently recorded actions in the audit logs."

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

query "activity_dashboard_failed_logins" {
  title       = "Top 10 Failed User Logins"
  description = "List the top 10 users with the most failed login attempts."

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
