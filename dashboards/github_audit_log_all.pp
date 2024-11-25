dashboard "github_audit_logs_all" {

  title = "GitHub Audit Logs"

  tags = merge(local.github_common_tags, {
    type = "Report"
  })

  container {

    input "detection_range" {
      title = "Select the date range:"
      type  = "date_range"
      width = 4
      # TODO: Do we need this sql arg?
      sql   = "select 1;"
    }

  }

  container {

    card {
      query = query.github_audit_logs_all_total_count
      width = 3
    }

  }

  container {
    table {
      query = query.github_audit_logs_all_with_principal
    }
  }

}

query "github_audit_logs_all_with_principal" {
  sql = <<-EOQ
    select
      tp_timestamp as timestamp,
      action as operation,
      --__RESOURCE_SQL__ as resource,
      actor as actor,
      tp_source_ip as source_ip,
      tp_index as organization,
      tp_id as source_id,
      *
    from
      github_audit_log
    order by
      tp_timestamp desc
  EOQ
}

query "github_audit_logs_all_total_count" {
  sql = <<-EOQ
    select
      'Log count' as label,
      count(*) as value
    from
      github_audit_log
  EOQ
}
