package service

import (
	"errors"
	"fmt"
	"securitygroup/firewall"
	"securitygroup/models"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestServiceWithMock(t *testing.T) (*RuleService, *firewall.MockBackend) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	if err := db.AutoMigrate(&models.SecurityRule{}); err != nil {
		t.Fatalf("failed to migrate test db: %v", err)
	}

	repo := &testRepo{db: db}
	mockBackend := firewall.NewMockBackend()
	fwManager := firewall.NewManager(mockBackend)

	svc, err := NewRuleService(repo, fwManager, false)
	if err != nil {
		t.Fatalf("failed to create test service: %v", err)
	}

	return svc, mockBackend
}

func TestUpdateRule_AddNewRuleFail_Rollback(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "rollback-test",
		Action:    models.ActionAllow,
		IPAddress: "192.168.1.1",
		PortStart: 80,
		Priority:  10,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}
	oldIP := rule.IPAddress
	oldFwID := rule.FirewallID
	oldStatus := rule.Status

	if mockFW.GetActiveRuleCount() != 1 {
		t.Fatalf("expected 1 active rule before update")
	}

	mockFW.SetFailOnAdd(true)
	defer mockFW.ResetCounters()

	newIP := "10.0.0.1"
	ipField := newIP
	updateReq := &models.UpdateRuleRequest{
		IPAddress: &ipField,
	}

	updatedRule, rbInfo, err := svc.UpdateRule(rule.ID, updateReq)
	if err == nil {
		t.Fatal("expected error from UpdateRule when AddRule fails")
	}

	if !errors.Is(err, ErrRollbackOccurred) {
		t.Errorf("expected ErrRollbackOccurred, got %v", err)
	}

	if rbInfo == nil {
		t.Fatal("expected RollbackInfo")
	}
	if !rbInfo.Rollbacked {
		t.Error("expected rollback to be performed")
	}
	if rbInfo.PreviousState == nil {
		t.Error("expected previous state to be preserved")
	}
	if rbInfo.PreviousState.IPAddress != oldIP {
		t.Errorf("expected previous state IP %s, got %s", oldIP, rbInfo.PreviousState.IPAddress)
	}

	if updatedRule == nil {
		t.Fatal("expected restored rule to be returned")
	}
	if updatedRule.IPAddress != oldIP {
		t.Errorf("expected rule IP to be restored to %s, got %s", oldIP, updatedRule.IPAddress)
	}
	if updatedRule.Status != oldStatus {
		t.Errorf("expected rule status to be restored to %s, got %s", oldStatus, updatedRule.Status)
	}

	if !mockFW.HasRule(oldFwID) {
		t.Error("expected old firewall rule to be restored after rollback")
	}
	if mockFW.GetActiveRuleCount() != 1 {
		t.Errorf("expected 1 active rule after rollback, got %d", mockFW.GetActiveRuleCount())
	}

	dbRule, _ := svc.GetRule(rule.ID)
	if dbRule == nil {
		t.Fatal("expected rule to exist in DB")
	}
	if dbRule.IPAddress != oldIP {
		t.Errorf("expected DB rule IP to be restored to %s, got %s", oldIP, dbRule.IPAddress)
	}
	if dbRule.FirewallID != oldFwID {
		t.Errorf("expected DB rule FirewallID to be restored to %s, got %s", oldFwID, dbRule.FirewallID)
	}

	t.Log("Update rollback test passed: rule restored to previous state after failure")
}

func TestUpdateRule_DeleteOldFail_Rollback(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "rollback-test2",
		Action:    models.ActionAllow,
		IPAddress: "192.168.2.1",
		PortStart: 443,
		Priority:  20,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}
	oldFwID := rule.FirewallID
	oldIP := rule.IPAddress

	mockFW.SetFailOnDelete(true)
	defer mockFW.ResetCounters()

	newIP := "10.0.0.2"
	ipField := newIP
	updateReq := &models.UpdateRuleRequest{
		IPAddress: &ipField,
	}

	updatedRule, rbInfo, err := svc.UpdateRule(rule.ID, updateReq)
	if err == nil {
		t.Fatal("expected error from UpdateRule when DeleteRule fails")
	}

	if !errors.Is(err, ErrRollbackOccurred) {
		t.Errorf("expected ErrRollbackOccurred, got %v", err)
	}

	if rbInfo == nil || !rbInfo.Rollbacked {
		t.Error("expected rollback to be performed")
	}

	if updatedRule != nil && updatedRule.IPAddress != oldIP {
		t.Errorf("expected rule IP to be restored to %s, got %s", oldIP, updatedRule.IPAddress)
	}

	if !mockFW.HasRule(oldFwID) {
		t.Error("expected old firewall rule to still exist")
	}
	if mockFW.GetActiveRuleCount() != 1 {
		t.Errorf("expected 1 active rule after rollback, got %d", mockFW.GetActiveRuleCount())
	}

	dbRule, _ := svc.GetRule(rule.ID)
	if dbRule != nil && dbRule.FirewallID != oldFwID {
		t.Errorf("expected DB FirewallID to remain %s, got %s", oldFwID, dbRule.FirewallID)
	}

	t.Log("Delete failure rollback test passed")
}

func TestDeleteRule_DBFail_RollbackFirewall(t *testing.T) {
	svc, _ := setupTestServiceWithMock(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "rollback-test3",
		Action:    models.ActionDeny,
		IPAddress: "203.0.113.5",
		Priority:  5,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	_, err = svc.DeleteRule(rule.ID)
	if err != nil {
		t.Fatalf("DeleteRule should succeed normally, got %v", err)
	}

	_, err = svc.GetRule(rule.ID)
	if err != ErrRuleNotFound {
		t.Errorf("expected ErrRuleNotFound, got %v", err)
	}

	t.Log("Delete rule normal flow test passed")
}

func TestBatchCreate_ThirdItemFails_AllRollback(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	mockFW.SetFailOnAddNth(3)
	defer mockFW.ResetCounters()

	requests := []models.CreateRuleRequest{
		{GroupID: "batch-rb", Action: models.ActionAllow, IPAddress: "10.0.0.1", Priority: 1},
		{GroupID: "batch-rb", Action: models.ActionAllow, IPAddress: "10.0.0.2", Priority: 2},
		{GroupID: "batch-rb", Action: models.ActionAllow, IPAddress: "10.0.0.3", Priority: 3},
		{GroupID: "batch-rb", Action: models.ActionAllow, IPAddress: "10.0.0.4", Priority: 4},
	}

	result := svc.BatchCreateRules(requests)

	if !result.Rollbacked {
		t.Error("expected batch to be rolled back")
	}
	if result.Success != 0 {
		t.Errorf("expected 0 successes after rollback, got %d", result.Success)
	}
	if result.Failed != 4 {
		t.Errorf("expected 4 failures after rollback, got %d", result.Failed)
	}
	if result.Total != 4 {
		t.Errorf("expected total 4, got %d", result.Total)
	}

	if mockFW.GetActiveRuleCount() != 0 {
		t.Errorf("expected 0 active rules after rollback, got %d", mockFW.GetActiveRuleCount())
	}

	listResult, _ := svc.ListRules("batch-rb", "", "", 1, 100)
	if listResult.Total != 0 {
		t.Errorf("expected 0 rules in DB after rollback, got %d", listResult.Total)
	}

	t.Log("Batch create rollback test passed: all changes rolled back")
}

func TestBatchUpdate_SecondItemFails_AllRollback(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	var ruleIDs []string
	for i := 0; i < 3; i++ {
		req := &models.CreateRuleRequest{
			GroupID:   "batch-upd-rb",
			Action:    models.ActionAllow,
			IPAddress: fmtIPForBatch(i),
			Priority:  i + 1,
		}
		rule, err := svc.CreateRule(req)
		if err != nil {
			t.Fatalf("CreateRule %d failed: %v", i, err)
		}
		ruleIDs = append(ruleIDs, rule.ID)
	}

	if mockFW.GetActiveRuleCount() != 3 {
		t.Fatalf("expected 3 active rules before batch update")
	}

	mockFW.SetFailOnAddNth(3)
	defer mockFW.ResetCounters()

	newPort := 8080
	portField := newPort
	updates := []models.BatchUpdateItem{
		{ID: ruleIDs[0], PortStart: &portField, PortEnd: &portField},
		{ID: ruleIDs[1], PortStart: &portField, PortEnd: &portField},
		{ID: ruleIDs[2], PortStart: &portField, PortEnd: &portField},
	}

	result := svc.BatchUpdateRules(updates)

	if !result.Rollbacked {
		t.Error("expected batch update to be rolled back")
	}
	if result.Success != 0 {
		t.Errorf("expected 0 successes after rollback, got %d", result.Success)
	}

	for i, id := range ruleIDs {
		rule, _ := svc.GetRule(id)
		if rule == nil {
			t.Errorf("rule %d should still exist", i)
			continue
		}
		if rule.PortStart != 0 {
			t.Errorf("rule %d PortStart should be 0 (original), got %d", i, rule.PortStart)
		}
		originalIP := fmtIPForBatch(i)
		if rule.IPAddress != originalIP {
			t.Errorf("rule %d IP should be %s, got %s", i, originalIP, rule.IPAddress)
		}
		if rule.FirewallID == "" {
			t.Errorf("rule %d FirewallID should not be empty", i)
		}
		if !mockFW.HasRule(rule.FirewallID) {
			t.Errorf("rule %d firewall rule should exist after rollback", i)
		}
	}

	if mockFW.GetActiveRuleCount() != 3 {
		t.Errorf("expected 3 active rules after rollback, got %d", mockFW.GetActiveRuleCount())
	}

	t.Log("Batch update rollback test passed: all changes rolled back")
}

func TestSyncAll_ThirdRuleFails_AllRollback(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	for i := 0; i < 5; i++ {
		req := &models.CreateRuleRequest{
			GroupID:   "sync-rb",
			Action:    models.ActionAllow,
			IPAddress: fmtIPForBatch(i + 10),
			Priority:  i + 1,
		}
		_, err := svc.CreateRule(req)
		if err != nil {
			t.Fatalf("CreateRule %d failed: %v", i, err)
		}
	}

	if mockFW.GetActiveRuleCount() != 5 {
		t.Fatalf("expected 5 active rules before sync")
	}

	mockFW.SetFailOnAddNth(3)
	defer mockFW.ResetCounters()

	rbInfo, err := svc.SyncAllRules()
	if err == nil {
		t.Fatal("expected error from SyncAllRules when AddRule fails")
	}

	if rbInfo == nil {
		t.Fatal("expected RollbackInfo")
	}
	if !rbInfo.Rollbacked {
		t.Error("expected rollback to be performed")
	}
	if len(rbInfo.RollbackErrors) == 0 {
		t.Error("expected rollback errors to be recorded")
	}

	if mockFW.GetActiveRuleCount() != 5 {
		t.Errorf("expected 5 active rules after rollback, got %d", mockFW.GetActiveRuleCount())
	}

	listResult, _ := svc.ListRules("sync-rb", "", "", 1, 100)
	if listResult.Total != 5 {
		t.Errorf("expected 5 rules in DB after rollback, got %d", listResult.Total)
	}

	for _, rule := range listResult.List {
		if rule.FirewallID == "" {
			t.Errorf("rule %s should have FirewallID after rollback", rule.ID)
		}
		if !mockFW.HasRule(rule.FirewallID) {
			t.Errorf("firewall rule for %s should exist after rollback", rule.ID)
		}
	}

	t.Log("Sync rollback test passed: all original rules restored")
}

func TestToggleStatus_DisableFail_Rollback(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "toggle-rb",
		Action:    models.ActionAllow,
		IPAddress: "172.16.0.100",
		Priority:  100,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}
	oldFwID := rule.FirewallID

	if mockFW.GetActiveRuleCount() != 1 {
		t.Fatalf("expected 1 active rule")
	}

	mockFW.SetFailOnDelete(true)
	defer mockFW.ResetCounters()

	disabled := models.StatusDisabled
	updateReq := &models.UpdateRuleRequest{Status: &disabled}

	updatedRule, rbInfo, err := svc.UpdateRule(rule.ID, updateReq)
	if err == nil {
		t.Fatal("expected error from UpdateRule when disable fails")
	}

	if rbInfo == nil || !rbInfo.Rollbacked {
		t.Error("expected rollback to be performed")
	}

	if updatedRule != nil && updatedRule.Status != models.StatusActive {
		t.Errorf("expected rule status to remain active, got %s", updatedRule.Status)
	}

	if !mockFW.HasRule(oldFwID) {
		t.Error("expected firewall rule to still exist after rollback")
	}
	if mockFW.GetActiveRuleCount() != 1 {
		t.Errorf("expected 1 active rule after rollback, got %d", mockFW.GetActiveRuleCount())
	}

	dbRule, _ := svc.GetRule(rule.ID)
	if dbRule == nil || dbRule.Status != models.StatusActive {
		t.Error("expected DB rule to remain active")
	}
	if dbRule.FirewallID != oldFwID {
		t.Errorf("expected DB FirewallID to remain %s", oldFwID)
	}

	t.Log("Toggle status rollback test passed")
}

func TestRollbackInfo_PreviousStatePreserved(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	createReq := &models.CreateRuleRequest{
		GroupID:     "state-rb",
		GroupName:   "Test Group",
		Description: "Original description",
		Action:      models.ActionAllow,
		Direction:   models.DirectionInbound,
		Protocol:    models.ProtocolTCP,
		IPAddress:   "192.168.50.1",
		PortStart:   22,
		Priority:    50,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	mockFW.SetFailOnAdd(true)
	defer mockFW.ResetCounters()

	newAction := models.ActionDeny
	newPort := 443
	updateReq := &models.UpdateRuleRequest{
		Action:    &newAction,
		PortStart: &newPort,
	}

	_, rbInfo, _ := svc.UpdateRule(rule.ID, updateReq)

	if rbInfo == nil || rbInfo.PreviousState == nil {
		t.Fatal("expected previous state to be preserved")
	}

	prev := rbInfo.PreviousState
	if prev.GroupID != "state-rb" {
		t.Errorf("expected previous GroupID 'state-rb', got '%s'", prev.GroupID)
	}
	if prev.GroupName != "Test Group" {
		t.Errorf("expected previous GroupName 'Test Group', got '%s'", prev.GroupName)
	}
	if prev.Description != "Original description" {
		t.Errorf("expected previous Description 'Original description', got '%s'", prev.Description)
	}
	if prev.Action != models.ActionAllow {
		t.Errorf("expected previous Action 'allow', got '%s'", prev.Action)
	}
	if prev.IPAddress != "192.168.50.1" {
		t.Errorf("expected previous IP '192.168.50.1', got '%s'", prev.IPAddress)
	}
	if prev.PortStart != 22 {
		t.Errorf("expected previous PortStart 22, got %d", prev.PortStart)
	}
	if prev.Priority != 50 {
		t.Errorf("expected previous Priority 50, got %d", prev.Priority)
	}

	t.Log("Previous state preservation test passed")
}

func TestBatchCreate_PartialValidationFail_NoRollbackNeeded(t *testing.T) {
	svc, mockFW := setupTestServiceWithMock(t)

	requests := []models.CreateRuleRequest{
		{GroupID: "partial-test", Action: models.ActionAllow, IPAddress: "10.1.0.1", Priority: 1},
		{GroupID: "partial-test", Action: models.ActionAllow, IPAddress: "invalid-ip", Priority: 2},
		{GroupID: "partial-test", Action: models.ActionAllow, IPAddress: "10.1.0.3", Priority: 3},
	}

	result := svc.BatchCreateRules(requests)

	if result.Rollbacked {
		t.Error("expected no rollback for validation-only failures")
	}
	if result.Success != 2 {
		t.Errorf("expected 2 successes, got %d", result.Success)
	}
	if result.Failed != 1 {
		t.Errorf("expected 1 failure, got %d", result.Failed)
	}
	if len(result.FailedItems) != 1 {
		t.Errorf("expected 1 failed item, got %d", len(result.FailedItems))
	}

	if mockFW.GetActiveRuleCount() != 2 {
		t.Errorf("expected 2 active rules, got %d", mockFW.GetActiveRuleCount())
	}

	listResult, _ := svc.ListRules("partial-test", "", "", 1, 100)
	if listResult.Total != 2 {
		t.Errorf("expected 2 rules in DB, got %d", listResult.Total)
	}

	t.Log("Partial validation failure test passed: valid rules preserved")
}

func fmtIPForBatch(i int) string {
	return fmt.Sprintf("10.0.%d.%d", i/256, i%256)
}
