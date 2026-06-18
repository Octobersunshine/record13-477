package service

import (
	"fmt"
	"securitygroup/firewall"
	"securitygroup/models"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestService(t *testing.T) (*RuleService, *firewall.MockBackend) {
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

type testRepo struct {
	db *gorm.DB
}

func (r *testRepo) Create(rule *models.SecurityRule) error {
	return r.db.Create(rule).Error
}

func (r *testRepo) GetByID(id string) (*models.SecurityRule, error) {
	var rule models.SecurityRule
	err := r.db.Where("id = ?", id).First(&rule).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &rule, nil
}

func (r *testRepo) List(groupID string, action string, status string, page int, pageSize int) (*models.RuleListResponse, error) {
	query := r.db.Model(&models.SecurityRule{})
	if groupID != "" {
		query = query.Where("group_id = ?", groupID)
	}
	if action != "" {
		query = query.Where("action = ?", action)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	var rules []models.SecurityRule
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	if err := query.Order("priority ASC, created_at DESC").Offset(offset).Limit(pageSize).Find(&rules).Error; err != nil {
		return nil, err
	}

	return &models.RuleListResponse{Total: total, List: rules}, nil
}

func (r *testRepo) Update(rule *models.SecurityRule) error {
	return r.db.Save(rule).Error
}

func (r *testRepo) Delete(id string) error {
	return r.db.Delete(&models.SecurityRule{}, "id = ?", id).Error
}

func (r *testRepo) ListAllActive() ([]models.SecurityRule, error) {
	var rules []models.SecurityRule
	err := r.db.Where("status = ?", models.StatusActive).Find(&rules).Error
	return rules, err
}

func TestCreateRule_Allow_Inbound(t *testing.T) {
	svc, mockFW := setupTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "test-group-1",
		GroupName: "Web Server",
		Action:    models.ActionAllow,
		Direction: models.DirectionInbound,
		Protocol:  models.ProtocolTCP,
		IPAddress: "192.168.1.100",
		PortStart: 80,
		PortEnd:   80,
		Priority:  10,
	}

	rule, err := svc.CreateRule(req)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	if rule.ID == "" {
		t.Error("expected non-empty rule ID")
	}
	if rule.GroupID != "test-group-1" {
		t.Errorf("expected group_id 'test-group-1', got '%s'", rule.GroupID)
	}
	if rule.Status != models.StatusActive {
		t.Errorf("expected status active, got %s", rule.Status)
	}
	if rule.FirewallID == "" {
		t.Error("expected firewall ID to be set for active rule")
	}

	if !mockFW.HasRule(rule.FirewallID) {
		t.Error("expected rule to exist in mock firewall backend")
	}

	t.Logf("Created rule: ID=%s, FirewallID=%s", rule.ID, rule.FirewallID)
}

func TestCreateRule_Deny_ImmediateEffect(t *testing.T) {
	svc, mockFW := setupTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "block-list",
		Action:    models.ActionDeny,
		Direction: models.DirectionInbound,
		IPAddress: "10.0.0.0/24",
		Priority:  1,
	}

	rule, err := svc.CreateRule(req)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	if rule.Action != models.ActionDeny {
		t.Errorf("expected action deny, got %s", rule.Action)
	}

	fwCount := mockFW.GetActiveRuleCount()
	if fwCount != 1 {
		t.Errorf("expected 1 active firewall rule, got %d", fwCount)
	}

	t.Logf("Deny rule created and applied immediately: %s", rule.FirewallID)
}

func TestUpdateRule_ModifyIP(t *testing.T) {
	svc, mockFW := setupTestService(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "update-test",
		Action:    models.ActionAllow,
		Direction: models.DirectionInbound,
		Protocol:  models.ProtocolTCP,
		IPAddress: "192.168.1.1",
		PortStart: 22,
		Priority:  50,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}
	oldFwID := rule.FirewallID
	t.Logf("Original rule: IP=%s, FirewallID=%s", rule.IPAddress, oldFwID)

	newIP := "192.168.1.2"
	ipField := newIP
	updateReq := &models.UpdateRuleRequest{
		IPAddress: &ipField,
	}

	updatedRule, err := svc.UpdateRule(rule.ID, updateReq)
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	if updatedRule.IPAddress != newIP {
		t.Errorf("expected IP %s, got %s", newIP, updatedRule.IPAddress)
	}

	if mockFW.HasRule(oldFwID) {
		t.Error("old firewall rule should have been removed")
	}

	if !mockFW.HasRule(updatedRule.FirewallID) {
		t.Error("new firewall rule should exist")
	}

	if updatedRule.FirewallID == oldFwID {
		t.Error("firewall ID should change after IP modification")
	}

	t.Logf("Updated rule: IP=%s, FirewallID=%s", updatedRule.IPAddress, updatedRule.FirewallID)
}

func TestUpdateRule_ToggleStatus_Disabled(t *testing.T) {
	svc, mockFW := setupTestService(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "toggle-test",
		Action:    models.ActionAllow,
		Direction: models.DirectionInbound,
		IPAddress: "172.16.0.1",
		Priority:  100,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}
	oldFwID := rule.FirewallID

	if mockFW.GetActiveRuleCount() != 1 {
		t.Fatalf("expected 1 active rule before disable")
	}

	disabled := models.StatusDisabled
	updateReq := &models.UpdateRuleRequest{Status: &disabled}

	updatedRule, err := svc.UpdateRule(rule.ID, updateReq)
	if err != nil {
		t.Fatalf("UpdateRule (disable) failed: %v", err)
	}

	if updatedRule.Status != models.StatusDisabled {
		t.Errorf("expected status disabled, got %s", updatedRule.Status)
	}
	if updatedRule.FirewallID != "" {
		t.Errorf("expected empty firewall ID after disable, got %s", updatedRule.FirewallID)
	}

	if mockFW.HasRule(oldFwID) {
		t.Error("firewall rule should have been removed after disabling")
	}
	if mockFW.GetActiveRuleCount() != 0 {
		t.Errorf("expected 0 active firewall rules after disable, got %d", mockFW.GetActiveRuleCount())
	}

	t.Log("Rule disabled and removed from firewall successfully")
}

func TestUpdateRule_ToggleStatus_ReEnable(t *testing.T) {
	svc, mockFW := setupTestService(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "reenable-test",
		Action:    models.ActionDeny,
		IPAddress: "203.0.113.0/24",
		Priority:  5,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}

	disabled := models.StatusDisabled
	_, err = svc.UpdateRule(rule.ID, &models.UpdateRuleRequest{Status: &disabled})
	if err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	if mockFW.GetActiveRuleCount() != 0 {
		t.Fatalf("expected 0 active rules after disable")
	}

	active := models.StatusActive
	updatedRule, err := svc.UpdateRule(rule.ID, &models.UpdateRuleRequest{Status: &active})
	if err != nil {
		t.Fatalf("Re-enable failed: %v", err)
	}

	if updatedRule.Status != models.StatusActive {
		t.Errorf("expected status active, got %s", updatedRule.Status)
	}
	if updatedRule.FirewallID == "" {
		t.Error("expected firewall ID after re-enable")
	}
	if mockFW.GetActiveRuleCount() != 1 {
		t.Errorf("expected 1 active firewall rule after re-enable, got %d", mockFW.GetActiveRuleCount())
	}

	t.Log("Rule re-enabled and applied to firewall successfully")
}

func TestDeleteRule_RemovesFromFirewall(t *testing.T) {
	svc, mockFW := setupTestService(t)

	createReq := &models.CreateRuleRequest{
		GroupID:   "delete-test",
		Action:    models.ActionAllow,
		Direction: models.DirectionOutbound,
		Protocol:  models.ProtocolUDP,
		IPAddress: "8.8.8.8",
		PortStart: 53,
		Priority:  200,
	}

	rule, err := svc.CreateRule(createReq)
	if err != nil {
		t.Fatalf("CreateRule failed: %v", err)
	}
	fwID := rule.FirewallID

	if !mockFW.HasRule(fwID) {
		t.Fatalf("expected firewall rule to exist before delete")
	}

	err = svc.DeleteRule(rule.ID)
	if err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	if mockFW.HasRule(fwID) {
		t.Error("firewall rule should be removed after delete")
	}
	if mockFW.GetActiveRuleCount() != 0 {
		t.Errorf("expected 0 active rules after delete, got %d", mockFW.GetActiveRuleCount())
	}

	_, err = svc.GetRule(rule.ID)
	if err != ErrRuleNotFound {
		t.Errorf("expected ErrRuleNotFound after delete, got %v", err)
	}

	t.Log("Rule deleted and removed from firewall successfully")
}

func TestCreateRule_InvalidPortRange(t *testing.T) {
	svc, _ := setupTestService(t)

	req := &models.CreateRuleRequest{
		GroupID:   "invalid-test",
		Action:    models.ActionAllow,
		IPAddress: "10.0.0.1",
		PortStart: 1000,
		PortEnd:   500,
		Priority:  100,
	}

	_, err := svc.CreateRule(req)
	if err == nil {
		t.Fatal("expected error for invalid port range, got nil")
	}
	if err != ErrInvalidInput {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}

	t.Logf("Correctly rejected invalid port range: %v", err)
}

func TestUpdateRule_NotFound(t *testing.T) {
	svc, _ := setupTestService(t)

	desc := "test"
	req := &models.UpdateRuleRequest{Description: &desc}

	_, err := svc.UpdateRule(uuid.New().String(), req)
	if err != ErrRuleNotFound {
		t.Errorf("expected ErrRuleNotFound, got %v", err)
	}
}

func TestSyncRules_CleanAndRebuild(t *testing.T) {
	svc, mockFW := setupTestService(t)

	for i := 0; i < 3; i++ {
		req := &models.CreateRuleRequest{
			GroupID:   "sync-test",
			Action:    models.ActionAllow,
			IPAddress: fmtIP(i),
			Priority:  i + 1,
		}
		_, err := svc.CreateRule(req)
		if err != nil {
			t.Fatalf("CreateRule %d failed: %v", i, err)
		}
	}

	if mockFW.GetActiveRuleCount() != 3 {
		t.Fatalf("expected 3 rules before sync, got %d", mockFW.GetActiveRuleCount())
	}

	err := svc.SyncAllRules()
	if err != nil {
		t.Fatalf("SyncAllRules failed: %v", err)
	}

	if mockFW.GetActiveRuleCount() != 3 {
		t.Errorf("expected 3 rules after sync, got %d", mockFW.GetActiveRuleCount())
	}

	t.Log("Sync completed successfully - rules rebuilt in firewall")
}

func TestListRules_WithFilters(t *testing.T) {
	svc, _ := setupTestService(t)

	_, _ = svc.CreateRule(&models.CreateRuleRequest{GroupID: "g1", Action: models.ActionAllow, IPAddress: "1.1.1.1", Priority: 1})
	_, _ = svc.CreateRule(&models.CreateRuleRequest{GroupID: "g1", Action: models.ActionDeny, IPAddress: "2.2.2.2", Priority: 2})
	_, _ = svc.CreateRule(&models.CreateRuleRequest{GroupID: "g2", Action: models.ActionAllow, IPAddress: "3.3.3.3", Priority: 3})

	result, err := svc.ListRules("", "", "", 1, 10)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 total rules, got %d", result.Total)
	}

	result, err = svc.ListRules("g1", "", "", 1, 10)
	if err != nil {
		t.Fatalf("ListRules with group filter failed: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 rules for g1, got %d", result.Total)
	}

	result, err = svc.ListRules("", "deny", "", 1, 10)
	if err != nil {
		t.Fatalf("ListRules with action filter failed: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 deny rule, got %d", result.Total)
	}

	t.Log("ListRules with various filters works correctly")
}

func fmtIP(i int) string {
	return fmt.Sprintf("10.0.0.%d", i+1)
}
