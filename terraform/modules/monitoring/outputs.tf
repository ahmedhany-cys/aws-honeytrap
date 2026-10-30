output "budget_names" {
  value = [aws_budgets_budget.monthly.name, aws_budgets_budget.account.name]
}
