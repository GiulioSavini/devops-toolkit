# IAM Access Analyzer "unused access" analyzer. This is the control that tells
# you which of the permissions you granted are not being used: unused roles,
# unused users, unused access keys and unused actions inside a policy.
#
# It is not free (charged per IAM role and user analysed per month), and it is
# not the same thing as external access analysis: an account can run one
# external-access analyzer and one unused-access analyzer side by side, and the
# unused-access one must be created explicitly.
#
# Findings are the input to a review, not an automation target. Deleting a role
# because a finding says it is unused is how you break the quarterly job.
locals {
  analyzer_type = "${var.scope}_UNUSED_ACCESS"

  # An empty analysis_rule block is not the same as no rule at all, so only
  # emit the block when there is something to exclude.
  has_exclusions = length(var.excluded_account_ids) > 0 || length(var.excluded_resource_tags) > 0
}

resource "aws_accessanalyzer_analyzer" "unused" {
  analyzer_name = var.analyzer_name
  type          = local.analyzer_type
  tags          = var.tags

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age

      dynamic "analysis_rule" {
        for_each = local.has_exclusions ? [1] : []

        content {
          dynamic "exclusion" {
            for_each = length(var.excluded_account_ids) > 0 ? [var.excluded_account_ids] : []

            content {
              account_ids = exclusion.value
            }
          }

          dynamic "exclusion" {
            for_each = var.excluded_resource_tags

            content {
              resource_tags = [exclusion.value]
            }
          }
        }
      }
    }
  }
}
