dashboard "github_delete_action_report" {

  title         = "GitHub Delete Action Report"
  #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

  container {

    card {
      query = query.codespaces_delete_count
      width = 3
    }

    card {
      query = query.environment_delete_count
      width = 3
    }

    card {
      query = query.project_delete_count
      width = 3
    }

    card {
      query = query.repo_destroy_count
      width = 3
    }
  }

 container {

  table {
    column "Actor" {
      #display = "none"
    }

    column "Action" {
      #display = "none"
    }

    column "Timestamp" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Repository" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Environment" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Project" {
      #display = "none"
      #href = "${dashboard.iam_user_detail.url_path}?input.user_arn={{.ARN | @uri}}"
    }

    column "Organization" {
      #display = "none"
    }

    query = query.github_delete_action_table
  }

}
}

query "github_delete_action_table" {
  sql = <<-EOQ
    select
      action as "Action",
      actor as "Actor",
      timestamp as "Timestamp",
      environment_name as "Environment",
      project_name as "Project",
      repo as "Repository",
      org as "Organization"
    from
      github_audit_log
    where
      action in ('codespaces.delete', 'environment.delete', 'project.delete', 'repo.destroy')
    order by
      action;
  EOQ
}

query "codespaces_delete_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'codespaces.delete' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      github_audit_log
    where
      action = 'codespaces.delete';
  EOQ
}

query "environment_delete_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'environment.delete' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      github_audit_log
    where
      action = 'environment.delete';
  EOQ
}

query "project_delete_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'project.delete' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      github_audit_log
    where
      action = 'project.delete';
  EOQ
}

query "repo_destroy_count" {
  sql = <<-EOQ
    select
      count(*) as value,
      'repo.destroy' as label,
      case count(*) when 0 then 'ok' else 'alert' end as "type"
    from
      github_audit_log
    where
      action = 'repo.destroy';
  EOQ
}
