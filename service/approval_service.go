package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"securitygroup/models"
	"securitygroup/repository"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrApprovalNotFound    = errors.New("approval request not found")
	ErrApprovalInvalidState = errors.New("invalid approval state for this operation")
	ErrApprovalRequired    = errors.New("approval required for high-risk operation")
	ErrNoApprovalNeeded    = errors.New("no approval needed for this operation")
)

const (
	HighPriorityThreshold    = 20
	CriticalPriorityThreshold = 5
	BatchHighRiskThreshold   = 5
	BatchCriticalThreshold   = 20
)

type ApprovalService struct {
	repo        repository.ApprovalRepository
	ruleService *RuleService
}

func NewApprovalService(repo repository.ApprovalRepository, ruleService *RuleService) *ApprovalService {
	return &ApprovalService{
		repo:        repo,
		ruleService: ruleService,
	}
}

func EvaluateCreateRisk(req *models.CreateRuleRequest) models.RiskLevel {
	risk := models.RiskLevelLow

	if req.Action == models.ActionDeny {
		risk = models.RiskLevelHigh
	}

	if isWildcardIP(req.IPAddress) {
		if req.Action == models.ActionDeny {
			return models.RiskLevelCritical
		}
		risk = models.RiskLevelHigh
	}

	if req.Priority > 0 && req.Priority <= CriticalPriorityThreshold {
		risk = models.RiskLevelCritical
	} else if req.Priority > 0 && req.Priority <= HighPriorityThreshold {
		if risk == models.RiskLevelLow {
			risk = models.RiskLevelMedium
		}
	}

	if req.PortStart == 0 && req.PortEnd == 0 && req.Protocol == models.ProtocolAny {
		if risk == models.RiskLevelHigh {
			risk = models.RiskLevelCritical
		} else if risk == models.RiskLevelLow {
			risk = models.RiskLevelMedium
		}
	}

	return risk
}

func EvaluateUpdateRisk(oldRule *models.SecurityRule, req *models.UpdateRuleRequest) models.RiskLevel {
	risk := models.RiskLevelLow

	if req.Action != nil && *req.Action == models.ActionDeny {
		risk = models.RiskLevelHigh
	}

	if req.IPAddress != nil && isWildcardIP(*req.IPAddress) {
		if req.Action != nil && *req.Action == models.ActionDeny {
			return models.RiskLevelCritical
		}
		risk = models.RiskLevelHigh
	}

	if req.Priority != nil {
		if *req.Priority <= CriticalPriorityThreshold {
			risk = models.RiskLevelCritical
		} else if *req.Priority <= HighPriorityThreshold {
			if risk == models.RiskLevelLow {
				risk = models.RiskLevelMedium
			}
		}
	}

	if req.Status != nil {
		if *req.Status == models.StatusActive && oldRule.Status == models.StatusDisabled {
			if oldRule.Action == models.ActionDeny {
				risk = models.RiskLevelHigh
			} else if risk == models.RiskLevelLow {
				risk = models.RiskLevelMedium
			}
		}
	}

	if req.Action != nil || req.IPAddress != nil || req.PortStart != nil || req.PortEnd != nil || req.Protocol != nil {
		if risk == models.RiskLevelLow {
			risk = models.RiskLevelMedium
		}
	}

	return risk
}

func EvaluateDeleteRisk(rule *models.SecurityRule) models.RiskLevel {
	if rule.Action == models.ActionAllow && isWildcardIP(rule.IPAddress) {
		return models.RiskLevelHigh
	}
	if rule.Action == models.ActionDeny {
		return models.RiskLevelMedium
	}
	return models.RiskLevelMedium
}

func EvaluateBatchCreateRisk(requests []models.CreateRuleRequest) models.RiskLevel {
	count := len(requests)
	if count >= BatchCriticalThreshold {
		return models.RiskLevelCritical
	}

	maxRisk := models.RiskLevelLow
	for _, req := range requests {
		r := EvaluateCreateRisk(&req)
		if riskLevelRank(r) > riskLevelRank(maxRisk) {
			maxRisk = r
		}
	}

	if count >= BatchHighRiskThreshold && riskLevelRank(maxRisk) < riskLevelRank(models.RiskLevelHigh) {
		maxRisk = models.RiskLevelHigh
	}

	return maxRisk
}

func EvaluateBatchUpdateRisk(updates []models.BatchUpdateItem, rules map[string]*models.SecurityRule) models.RiskLevel {
	count := len(updates)
	if count >= BatchCriticalThreshold {
		return models.RiskLevelCritical
	}

	maxRisk := models.RiskLevelLow
	for _, update := range updates {
		rule, ok := rules[update.ID]
		if !ok {
			continue
		}
		r := EvaluateUpdateRisk(rule, updateToUpdateRequest(&update))
		if riskLevelRank(r) > riskLevelRank(maxRisk) {
			maxRisk = r
		}
	}

	if count >= BatchHighRiskThreshold && riskLevelRank(maxRisk) < riskLevelRank(models.RiskLevelHigh) {
		maxRisk = models.RiskLevelHigh
	}

	return maxRisk
}

func IsHighRisk(risk models.RiskLevel) bool {
	return riskLevelRank(risk) >= riskLevelRank(models.RiskLevelHigh)
}

func riskLevelRank(r models.RiskLevel) int {
	switch r {
	case models.RiskLevelLow:
		return 1
	case models.RiskLevelMedium:
		return 2
	case models.RiskLevelHigh:
		return 3
	case models.RiskLevelCritical:
		return 4
	default:
		return 0
	}
}

func isWildcardIP(ip string) bool {
	return strings.Contains(ip, "0.0.0.0/0") || strings.Contains(ip, "::/0") || ip == "0.0.0.0" || ip == "::"
}

func updateToUpdateRequest(item *models.BatchUpdateItem) *models.UpdateRuleRequest {
	return &models.UpdateRuleRequest{
		GroupName:   item.GroupName,
		Description: item.Description,
		Action:      item.Action,
		Direction:   item.Direction,
		Protocol:    item.Protocol,
		IPAddress:   item.IPAddress,
		PortStart:   item.PortStart,
		PortEnd:     item.PortEnd,
		Priority:    item.Priority,
		Status:      item.Status,
	}
}

func (s *ApprovalService) CreateApproval(req *models.CreateApprovalRequest) (*models.ApprovalRequest, error) {
	now := time.Now()
	approval := &models.ApprovalRequest{
		ID:            uuid.New().String(),
		Title:         req.Title,
		Description:   req.Description,
		OperationType: req.OperationType,
		RiskLevel:     models.RiskLevelMedium,
		Status:        models.ApprovalPending,
		Applicant:     req.Applicant,
		RuleID:        req.RuleID,
		NewRuleData:   req.NewRuleData,
		SubmittedAt:   &now,
	}

	if err := s.repo.Create(approval); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) CreateApprovalForCreate(req *models.CreateRuleRequest, applicant string) (*models.ApprovalRequest, error) {
	risk := EvaluateCreateRisk(req)
	if !IsHighRisk(risk) {
		return nil, ErrNoApprovalNeeded
	}

	ruleData, _ := json.Marshal(req)

	title := fmt.Sprintf("创建规则 - %s %s %s", req.Action, req.IPAddress, req.GroupID)
	approval := &models.ApprovalRequest{
		ID:            uuid.New().String(),
		Title:         title,
		Description:   fmt.Sprintf("风险等级: %s", risk),
		OperationType: models.ApprovalOpCreate,
		RiskLevel:     risk,
		Status:        models.ApprovalPending,
		Applicant:     applicant,
		NewRuleData:   string(ruleData),
	}

	now := time.Now()
	approval.SubmittedAt = &now

	if err := s.repo.Create(approval); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) CreateApprovalForUpdate(ruleID string, req *models.UpdateRuleRequest, applicant string) (*models.ApprovalRequest, error) {
	rule, err := s.ruleService.GetRule(ruleID)
	if err != nil {
		return nil, err
	}

	risk := EvaluateUpdateRisk(rule, req)
	if !IsHighRisk(risk) {
		return nil, ErrNoApprovalNeeded
	}

	ruleSnapshot, _ := json.Marshal(rule)
	newRuleData, _ := json.Marshal(req)

	title := fmt.Sprintf("修改规则 - %s", ruleID[:8])
	approval := &models.ApprovalRequest{
		ID:            uuid.New().String(),
		Title:         title,
		Description:   fmt.Sprintf("风险等级: %s", risk),
		OperationType: models.ApprovalOpUpdate,
		RiskLevel:     risk,
		Status:        models.ApprovalPending,
		Applicant:     applicant,
		RuleID:        ruleID,
		RuleSnapshot:  string(ruleSnapshot),
		NewRuleData:   string(newRuleData),
	}

	now := time.Now()
	approval.SubmittedAt = &now

	if err := s.repo.Create(approval); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) CreateApprovalForDelete(ruleID string, applicant string) (*models.ApprovalRequest, error) {
	rule, err := s.ruleService.GetRule(ruleID)
	if err != nil {
		return nil, err
	}

	risk := EvaluateDeleteRisk(rule)
	if !IsHighRisk(risk) {
		return nil, ErrNoApprovalNeeded
	}

	ruleSnapshot, _ := json.Marshal(rule)

	title := fmt.Sprintf("删除规则 - %s", ruleID[:8])
	approval := &models.ApprovalRequest{
		ID:            uuid.New().String(),
		Title:         title,
		Description:   fmt.Sprintf("风险等级: %s", risk),
		OperationType: models.ApprovalOpDelete,
		RiskLevel:     risk,
		Status:        models.ApprovalPending,
		Applicant:     applicant,
		RuleID:        ruleID,
		RuleSnapshot:  string(ruleSnapshot),
	}

	now := time.Now()
	approval.SubmittedAt = &now

	if err := s.repo.Create(approval); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) GetApproval(id string) (*models.ApprovalRequest, error) {
	approval, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, ErrApprovalNotFound
	}
	return approval, nil
}

func (s *ApprovalService) ListApprovals(status string, operationType string, applicant string, page int, pageSize int) (*models.ApprovalListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.List(status, operationType, applicant, page, pageSize)
}

func (s *ApprovalService) Approve(id string, approver string, remark string) (*models.ApprovalRequest, error) {
	approval, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, ErrApprovalNotFound
	}

	if approval.Status != models.ApprovalPending {
		return nil, fmt.Errorf("%w: current status is %s", ErrApprovalInvalidState, approval.Status)
	}

	approval.Status = models.ApprovalApproved
	approval.Approver = approver
	approval.ApprovalRemark = remark
	now := time.Now()
	approval.ApprovedAt = &now

	if err := s.repo.Update(approval); err != nil {
		return nil, fmt.Errorf("failed to update approval: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) Reject(id string, approver string, remark string) (*models.ApprovalRequest, error) {
	approval, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, ErrApprovalNotFound
	}

	if approval.Status != models.ApprovalPending {
		return nil, fmt.Errorf("%w: current status is %s", ErrApprovalInvalidState, approval.Status)
	}

	approval.Status = models.ApprovalRejected
	approval.Approver = approver
	approval.ApprovalRemark = remark
	now := time.Now()
	approval.ApprovedAt = &now

	if err := s.repo.Update(approval); err != nil {
		return nil, fmt.Errorf("failed to update approval: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) Execute(id string) (interface{}, *RollbackInfo, error) {
	approval, err := s.repo.GetByID(id)
	if err != nil {
		return nil, nil, err
	}
	if approval == nil {
		return nil, nil, ErrApprovalNotFound
	}

	if approval.Status != models.ApprovalApproved {
		return nil, nil, fmt.Errorf("%w: current status is %s, must be approved first", ErrApprovalInvalidState, approval.Status)
	}

	var result interface{}
	var rbInfo *RollbackInfo
	var execErr error

	switch approval.OperationType {
	case models.ApprovalOpCreate:
		result, rbInfo, execErr = s.executeCreate(approval)
	case models.ApprovalOpUpdate:
		result, rbInfo, execErr = s.executeUpdate(approval)
	case models.ApprovalOpDelete:
		result, rbInfo, execErr = s.executeDelete(approval)
	case models.ApprovalOpBatchCreate:
		result, rbInfo, execErr = s.executeBatchCreate(approval)
	case models.ApprovalOpBatchUpdate:
		result, rbInfo, execErr = s.executeBatchUpdate(approval)
	case models.ApprovalOpSync:
		result, rbInfo, execErr = s.executeSync(approval)
	default:
		return nil, nil, fmt.Errorf("unsupported operation type: %s", approval.OperationType)
	}

	now := time.Now()
	if execErr != nil {
		approval.Status = models.ApprovalFailed
		approval.ErrorMsg = execErr.Error()
	} else {
		approval.Status = models.ApprovalExecuted
		approval.ExecutedAt = &now
	}
	_ = s.repo.Update(approval)

	return result, rbInfo, execErr
}

func (s *ApprovalService) executeCreate(approval *models.ApprovalRequest) (*models.SecurityRule, *RollbackInfo, error) {
	var req models.CreateRuleRequest
	if err := json.Unmarshal([]byte(approval.NewRuleData), &req); err != nil {
		return nil, nil, fmt.Errorf("failed to parse new rule data: %w", err)
	}

	rule, err := s.ruleService.CreateRule(&req)
	if err != nil {
		return rule, nil, err
	}
	return rule, nil, nil
}

func (s *ApprovalService) executeUpdate(approval *models.ApprovalRequest) (*models.SecurityRule, *RollbackInfo, error) {
	var req models.UpdateRuleRequest
	if err := json.Unmarshal([]byte(approval.NewRuleData), &req); err != nil {
		return nil, nil, fmt.Errorf("failed to parse update request: %w", err)
	}

	rule, rbInfo, err := s.ruleService.UpdateRule(approval.RuleID, &req)
	return rule, rbInfo, err
}

func (s *ApprovalService) executeDelete(approval *models.ApprovalRequest) (interface{}, *RollbackInfo, error) {
	rbInfo, err := s.ruleService.DeleteRule(approval.RuleID)
	return map[string]string{"id": approval.RuleID}, rbInfo, err
}

func (s *ApprovalService) executeBatchCreate(approval *models.ApprovalRequest) (*BatchResult, *RollbackInfo, error) {
	var requests []models.CreateRuleRequest
	if err := json.Unmarshal([]byte(approval.NewRuleData), &requests); err != nil {
		return nil, nil, fmt.Errorf("failed to parse batch create data: %w", err)
	}

	result := s.ruleService.BatchCreateRules(requests)
	return result, nil, nil
}

func (s *ApprovalService) executeBatchUpdate(approval *models.ApprovalRequest) (*BatchResult, *RollbackInfo, error) {
	var updates []models.BatchUpdateItem
	if err := json.Unmarshal([]byte(approval.NewRuleData), &updates); err != nil {
		return nil, nil, fmt.Errorf("failed to parse batch update data: %w", err)
	}

	result := s.ruleService.BatchUpdateRules(updates)
	return result, nil, nil
}

func (s *ApprovalService) executeSync(approval *models.ApprovalRequest) (interface{}, *RollbackInfo, error) {
	rbInfo, err := s.ruleService.SyncAllRules()
	return map[string]bool{"synced": err == nil}, rbInfo, err
}

func (s *ApprovalService) Cancel(id string) (*models.ApprovalRequest, error) {
	approval, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, ErrApprovalNotFound
	}

	if approval.Status != models.ApprovalPending {
		return nil, fmt.Errorf("%w: current status is %s, only pending can be cancelled", ErrApprovalInvalidState, approval.Status)
	}

	approval.Status = models.ApprovalCancelled

	if err := s.repo.Update(approval); err != nil {
		return nil, fmt.Errorf("failed to update approval: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) CreateApprovalForBatchCreate(requests []models.CreateRuleRequest, applicant string) (*models.ApprovalRequest, error) {
	risk := EvaluateBatchCreateRisk(requests)
	if !IsHighRisk(risk) {
		return nil, ErrNoApprovalNeeded
	}

	ruleData, _ := json.Marshal(requests)

	title := fmt.Sprintf("批量创建规则 - %d 条", len(requests))
	approval := &models.ApprovalRequest{
		ID:            uuid.New().String(),
		Title:         title,
		Description:   fmt.Sprintf("风险等级: %s, 共 %d 条规则", risk, len(requests)),
		OperationType: models.ApprovalOpBatchCreate,
		RiskLevel:     risk,
		Status:        models.ApprovalPending,
		Applicant:     applicant,
		NewRuleData:   string(ruleData),
	}

	now := time.Now()
	approval.SubmittedAt = &now

	if err := s.repo.Create(approval); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	return approval, nil
}

func (s *ApprovalService) CreateApprovalForBatchUpdate(updates []models.BatchUpdateItem, applicant string) (*models.ApprovalRequest, error) {
	rules := make(map[string]*models.SecurityRule)
	for _, update := range updates {
		rule, err := s.ruleService.GetRule(update.ID)
		if err == nil && rule != nil {
			rules[update.ID] = rule
		}
	}

	risk := EvaluateBatchUpdateRisk(updates, rules)
	if !IsHighRisk(risk) {
		return nil, ErrNoApprovalNeeded
	}

	ruleData, _ := json.Marshal(updates)

	title := fmt.Sprintf("批量修改规则 - %d 条", len(updates))
	approval := &models.ApprovalRequest{
		ID:            uuid.New().String(),
		Title:         title,
		Description:   fmt.Sprintf("风险等级: %s, 共 %d 条规则", risk, len(updates)),
		OperationType: models.ApprovalOpBatchUpdate,
		RiskLevel:     risk,
		Status:        models.ApprovalPending,
		Applicant:     applicant,
		NewRuleData:   string(ruleData),
	}

	now := time.Now()
	approval.SubmittedAt = &now

	if err := s.repo.Create(approval); err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	return approval, nil
}
