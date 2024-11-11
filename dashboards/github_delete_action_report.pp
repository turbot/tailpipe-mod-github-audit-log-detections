# dashboard "github_delete_action_report" {

#   title         = "GitHub Delete Action Report"
#   #documentation = file("./dashboards/iam/docs/iam_user_report_mfa.md")

#    container {
#     table {
#       query = query.github_delete_action_table
#     }
#   }
# }

# locals {
#   # Store the replace logic in a local variable
#   github_delete_action_table_sql = replace(
#     local.common_dimensions_audit_log_sql,
#     "__RESOURCE_SQL__",
#     <<-EOT
#       case
#         when action = 'codespaces.destroy' then repo -- TODO: What column to show?
#         when action = 'environment.delete' then environment_name
#         when action = 'project.delete' then project_name
#         when action = 'repo.destroy' then repo
#       end
#     EOT
#   )
# }

# query "github_delete_action_table" {
#   sql = <<-EOQ
#     select
#       ${local.github_delete_action_table_sql}
#       -- Additional dimensions
#     from
#       github_audit_log
#     where
#       action in ('codespaces.destroy', 'environment.delete', 'project.delete', 'repo.destroy')
#     order by
#       timestamp desc;
#   EOQ
# }
