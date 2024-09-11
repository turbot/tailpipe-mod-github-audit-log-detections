dashboard "github_delete_action_report" {

  title         = "GitHub Delete Action Report"
  #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

   container {
    table {
      query = query.github_delete_action_table
    }
  }
}

query "github_delete_action_table" {
  sql = <<-EOQ
    select
      timestamp as timestamp, -- TODO: Use tp_timestamp once the value is fixed
      actor as actor,
      actor_ip as source_ip_address,
      --tp_source_ip as source_ip_address,
      action as operation,
      case
        when action = 'codespaces.destroy' then array_value(repo)::JSON -- TODO: What column to show?
        when action = 'environment.delete' then array_value(environment_name)::JSON
        when action = 'project.delete' then array_value(project_name)::JSON
        when action = 'repo.destroy' then array_value(repo)::JSON
      end as resources,
      repo as index, -- TODO: Would tp_index have this info?
      tp_id as tp_log_id,
      -- Additional dimensions
    from
      github_audit_log
    where
      action in ('codespaces.destroy', 'environment.delete', 'project.delete', 'repo.destroy')
    order by
      timestamp desc;
  EOQ
}
