package service

import (
	"securitygroup/firewall"
	"securitygroup/models"
	"securitygroup/repository"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupApprovalTestService(t *testing.T) (*ApprovalService, *RuleService, *firewall.MockBackend) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	if err := db.AutoMigrate(&models.SecurityRule{}, &models.ApprovalRequest{}); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	ruleRepo := repository.NewSQLiteRepositoryWithDB(db)
	approvalRepo := repository.NewSQLiteApprovalRepository(db)

	mockFW := firewall.NewMockBackend()
	fwManager := firewall.NewManager(mockFW)

	ruleSvc, err := NewRuleService(ruleRepo, fwManager, false)
	if err != nil {
		t.Fatalf("failed to create rule service: %v", err)
	}

	approvalSvc := NewApprovalService(approvalRepo, ruleSvc)

	return approvalSvc, ruleSvc, mockFW
}

func TestEvaluateCreateRisk_DenyHighRisk(t *testing.T) {
	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	risk := EvaluateCreateRisk(req)
	if risk != models.RiskLevelHigh {
		t.Errorf("expected high risk for deny rule, got %s", risk)
	}
	if !IsHighRisk(risk) {
		t.Error("expected IsHighRisk to be true for deny rule")
	}
}

func TestEvaluateCreateRisk_DenyWildcardCritical(t *testing.T) {
	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "0.0.0.0/0",
		Priority:  100,
	}

	risk := EvaluateCreateRisk(req)
	if risk != models.RiskLevelCritical {
		t.Errorf("expected critical risk for deny wildcard rule, got %s", risk)
	}
}

func TestEvaluateCreateRisk_AllowLowRisk(t *testing.T) {
	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionAllow,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	risk := EvaluateCreateRisk(req)
	if risk != models.RiskLevelLow {
		t.Errorf("expected low risk for allow rule, got %s", risk)
	}
	if IsHighRisk(risk) {
		t.Error("expected IsHighRisk to be false for low risk allow rule")
	}
}

func TestEvaluateCreateRisk_HighPriorityCritical(t *testing.T) {
	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionAllow,
		IPAddress: "10.0.0.1",
		Priority:  3,
	}

	risk := EvaluateCreateRisk(req)
	if risk != models.RiskLevelCritical {
		t.Errorf("expected critical risk for priority <= 5, got %s", risk)
	}
}

func TestCreateApprovalForCreate_HighRisk(t *testing.T) {
	approvalSvc, _, _ := setupApprovalTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	approval, err := approvalSvc.CreateApprovalForCreate(req, "test-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if approval == nil {
		t.Fatal("expected approval to be created for high risk rule")
	}
	if approval.Status != models.ApprovalPending {
		t.Errorf("expected pending status, got %s", approval.Status)
	}
	if approval.RiskLevel != models.RiskLevelHigh {
		t.Errorf("expected high risk level, got %s", approval.RiskLevel)
	}
	if approval.Applicant != "test-user" {
		t.Errorf("expected applicant test-user, got %s", approval.Applicant)
	}
}

func TestCreateApprovalForCreate_LowRiskNoApproval(t *testing.T) {
	approvalSvc, _, _ := setupApprovalTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionAllow,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	approval, err := approvalSvc.CreateApprovalForCreate(req, "test-user")
	if err == nil {
		t.Fatal("expected ErrNoApprovalNeeded error")
	}
	if approval != nil {
		t.Error("expected no approval for low risk rule")
	}
}

func TestApproveApproval(t *testing.T) {
	approvalSvc, _, _ := setupApprovalTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	approval, err := approvalSvc.CreateApprovalForCreate(req, "test-user")
	if err != nil {
		t.Fatalf("failed to create approval: %v", err)
	}

	approved, err := approvalSvc.Approve(approval.ID, "admin-user", "looks good")
	if err != nil {
		t.Fatalf("failed to approve: %v", err)
	}
	if approved.Status != models.ApprovalApproved {
		t.Errorf("expected approved status, got %s", approved.Status)
	}
	if approved.Approver != "admin-user" {
		t.Errorf("expected approver admin-user, got %s", approved.Approver)
	}
	if approved.ApprovalRemark != "looks good" {
		t.Errorf("expected remark 'looks good', got %s", approved.ApprovalRemark)
	}
}

func TestRejectApproval(t *testing.T) {
	approvalSvc, _, _ := setupApprovalTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	approval, err := approvalSvc.CreateApprovalForCreate(req, "test-user")
	if err != nil {
		t.Fatalf("failed to create approval: %v", err)
	}

	rejected, err := approvalSvc.Reject(approval.ID, "admin-user", "not allowed")
	if err != nil {
		t.Fatalf("failed to reject: %v", err)
	}
	if rejected.Status != models.ApprovalRejected {
		t.Errorf("expected rejected status, got %s", rejected.Status)
	}
	if rejected.Approver != "admin-user" {
		t.Errorf("expected approver admin-user, got %s", rejected.Approver)
	}
}

func TestExecuteApprovedCreate(t *testing.T) {
	approvalSvc, ruleSvc, mockFW := setupApprovalTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	approval, err := approvalSvc.CreateApprovalForCreate(req, "test-user")
	if err != nil {
		t.Fatalf("failed to create approval: %v", err)
	}

	_, err = approvalSvc.Approve(approval.ID, "admin-user", "ok")
	if err != nil {
		t.Fatalf("failed to approve: %v", err)
	}

	result, _, err := approvalSvc.Execute(approval.ID)
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}

	rule, ok := result.(*models.SecurityRule)
	if !ok {
		t.Fatal("expected result to be *models.SecurityRule")
	}

	if rule.IPAddress != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", rule.IPAddress)
	}

	if mockFW.GetActiveRuleCount() != 1 {
		t.Errorf("expected 1 active rule in firewall, got %d", mockFW.GetActiveRuleCount())
	}

	dbRule, _ := ruleSvc.GetRule(rule.ID)
	if dbRule == nil {
		t.Error("expected rule to exist in DB")
	}

	updatedApproval, _ := approvalSvc.GetApproval(approval.ID)
	if updatedApproval.Status != models.ApprovalExecuted {
		t.Errorf("expected executed status, got %s", updatedApproval.Status)
	}
}

func TestExecuteApprovedUpdate(t *testing.T) {
	approvalSvc, ruleSvc, mockFW := setupApprovalTestService(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionAllow,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}
	rule, err := ruleSvc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	updateReq := &models.UpdateRuleRequest{
		Action:    ptrAction(models.ActionDeny),
		IPAddress: ptrString("0.0.0.0/0"),
	}

	approval, err := approvalSvc.CreateApprovalForUpdate(rule.ID, updateReq, "test-user")
	if err != nil {
		t.Fatalf("failed to create approval: %v", err)
	}
	if approval == nil {
		t.Fatal("expected approval for high risk update")
	}

	_, err = approvalSvc.Approve(approval.ID, "admin-user", "ok")
	if err != nil {
		t.Fatalf("failed to approve: %v", err)
	}

	result, _, err := approvalSvc.Execute(approval.ID)
	if err != nil {
		t.Fatalf("failed to execute: %v", err)
	}

	updatedRule, ok := result.(*models.SecurityRule)
	if !ok {
		t.Fatal("expected result to be *models.SecurityRule")
	}

	if updatedRule.Action != models.ActionDeny {
		t.Errorf("expected action deny, got %s", updatedRule.Action)
	}
	if updatedRule.IPAddress != "0.0.0.0/0" {
		t.Errorf("expected IP 0.0.0.0/0, got %s", updatedRule.IPAddress)
	}

	if mockFW.GetActiveRuleCount() != 1 {
		t.Errorf("expected 1 active rule, got %d", mockFW.GetActiveRuleCount())
	}
}

func TestCancelApproval(t *testing.T) {
	approvalSvc, _, _ := setupApprovalTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	approval, err := approvalSvc.CreateApprovalForCreate(req, "test-user")
	if err != nil {
		t.Fatalf("failed to create approval: %v", err)
	}

	cancelled, err := approvalSvc.Cancel(approval.ID)
	if err != nil {
		t.Fatalf("failed to cancel: %v", err)
	}
	if cancelled.Status != models.ApprovalCancelled {
		t.Errorf("expected cancelled status, got %s", cancelled.Status)
	}
}

func TestApproveAlreadyApproved_Fails(t *testing.T) {
	approvalSvc, _, _ := setupApprovalTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-sg",
		Action:    models.ActionDeny,
		IPAddress: "10.0.0.1",
		Priority:  100,
	}

	approval, err := approvalSvc.CreateApprovalForCreate(req, "test-user")
	if err != nil {
		t.Fatalf("failed to create approval: %v", err)
	}

	_, err = approvalSvc.Approve(approval.ID, "admin-user", "ok")
	if err != nil {
		t.Fatalf("first approve should succeed: %v", err)
	}

	_, err = approvalSvc.Approve(approval.ID, "admin-user", "again")
	if err == nil {
		t.Fatal("expected error when approving already approved approval")
	}
}

func TestBatchCreateRisk_ManyItemsHighRisk(t *testing.T) {
	var requests []models.CreateRuleRequest
	for i := 0; i < 6; i++ {
		requests = append(requests, models.CreateRuleRequest{
			GroupID:   "test-sg",
			Action:    models.ActionAllow,
			IPAddress: "10.0.0.1",
			Priority:  100,
		})
	}

	risk := EvaluateBatchCreateRisk(requests)
	if !IsHighRisk(risk) {
		t.Errorf("expected high risk for 6 items, got %s", risk)
	}
}

func TestBatchCreateRisk_FewItemsLowRisk(t *testing.T) {
	var requests []models.CreateRuleRequest
	for i := 0; i < 3; i++ {
		requests = append(requests, models.CreateRuleRequest{
			GroupID:   "test-sg",
			Action:    models.ActionAllow,
			IPAddress: "10.0.0.1",
			Priority:  100,
		})
	}

	risk := EvaluateBatchCreateRisk(requests)
	if IsHighRisk(risk) {
		t.Errorf("expected low/medium risk for 3 low-risk items, got %s", risk)
	}
}

func ptrAction(a models.RuleAction) *models.RuleAction {
	return &a
}

func ptrString(s string) *string {
	return &s
}
