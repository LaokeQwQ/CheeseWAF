package engine

import "sync/atomic"

// budgetExhaustedPass counts requests that were forwarded upstream even though
// the detection pipeline could not finish analysing them.
//
// A WAF that silently forwards un-analysed traffic is indistinguishable from no
// WAF at all, so this counter exists to make every fail-open observable. It is
// exported as cheesewaf_waf_budget_exhausted_pass_total and should be alerted
// on: sustained non-zero values mean someone is exhausting the detection budget
// on purpose to switch the WAF off.
var budgetExhaustedPass atomic.Uint64

// RecordBudgetExhaustedPass records one request that was forwarded upstream
// after the detection budget ran out. The proxy calls this from the explicit
// ActionLog branch so that "allow" stays a decision rather than a fallthrough.
func RecordBudgetExhaustedPass() {
	budgetExhaustedPass.Add(1)
}

// ProcessBudgetExhaustedPass returns the number of budget-exhausted requests
// forwarded upstream for this process lifetime.
func ProcessBudgetExhaustedPass() uint64 {
	return budgetExhaustedPass.Load()
}

// ResetBudgetExhaustedPassForTest clears the process counter for isolated tests.
// Used by the proxy's fail-open tests, which assert on an exact count.
func ResetBudgetExhaustedPassForTest() {
	budgetExhaustedPass.Store(0)
}
