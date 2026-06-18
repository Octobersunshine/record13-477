package service

import (
	"errors"
	"fmt"
	"securitygroup/firewall"
	"securitygroup/models"
	"securitygroup/repository"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrRuleNotFound     = errors.New("rule not found")
	ErrInvalidInput     = errors.New("invalid input")
	ErrFirewallApply    = errors.New("failed to apply firewall rule")
	ErrRollbackOccurred = errors.New("operation failed and rolled back to previous state")
)

type RollbackInfo struct {
	Success        bool
	Rollbacked     bool
	RollbackErrors []error
	PreviousState  *models.SecurityRule
}

type BatchResult struct {
	Success      int
	Failed       int
	Total        int
	FailedItems  []BatchFailedItem
	Rollbacked   bool
	RollbackErrs []error
}

type BatchFailedItem struct {
	Index   int
	RuleID  string
	Message string
}

type RuleService struct {
	repo     repository.RuleRepository
	fw       *firewall.Manager
	autoSync bool
}

func NewRuleService(repo repository.RuleRepository, fw *firewall.Manager, autoSync bool) (*RuleService, error) {
	svc := &RuleService{
		repo:     repo,
		fw:       fw,
		autoSync: autoSync,
	}

	if autoSync {
		if err := svc.syncAllRulesToFirewall(); err != nil {
			return nil, fmt.Errorf("initial sync failed: %w", err)
		}
	}

	return svc, nil
}

func (s *RuleService) BackendName() string {
	return s.fw.BackendName()
}

func (s *RuleService) CreateRule(req *models.CreateRuleRequest) (*models.SecurityRule, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}

	rule := &models.SecurityRule{
		ID:          uuid.New().String(),
		GroupID:     req.GroupID,
		GroupName:   req.GroupName,
		Description: req.Description,
		Action:      req.Action,
		Direction:   req.Direction,
		Protocol:    req.Protocol,
		IPAddress:   req.IPAddress,
		PortStart:   req.PortStart,
		PortEnd:     req.PortEnd,
		Priority:    req.Priority,
		Status:      models.StatusActive,
	}

	if rule.Direction == "" {
		rule.Direction = models.DirectionInbound
	}
	if rule.Protocol == "" {
		rule.Protocol = models.ProtocolAny
	}
	if rule.Priority == 0 {
		rule.Priority = 100
	}

	if err := s.fw.ApplyCreate(rule); err != nil {
		rule.Status = models.StatusError
		rule.ErrorMsg = err.Error()
		if saveErr := s.repo.Create(rule); saveErr != nil {
			return nil, fmt.Errorf("create db failed after fw error: %w (original fw error: %v)", saveErr, err)
		}
		return rule, fmt.Errorf("%w: %v", ErrFirewallApply, err)
	}

	if err := s.repo.Create(rule); err != nil {
		_ = s.fw.ApplyDelete(rule)
		return nil, fmt.Errorf("db create failed: %w", err)
	}

	return rule, nil
}

func (s *RuleService) GetRule(id string) (*models.SecurityRule, error) {
	rule, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}
	return rule, nil
}

func (s *RuleService) ListRules(groupID string, action string, status string, page int, pageSize int) (*models.RuleListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.List(groupID, action, status, page, pageSize)
}

func (s *RuleService) UpdateRule(id string, req *models.UpdateRuleRequest) (*models.SecurityRule, *RollbackInfo, error) {
	oldRule, err := s.repo.GetByID(id)
	if err != nil {
		return nil, nil, err
	}
	if oldRule == nil {
		return nil, nil, ErrRuleNotFound
	}

	oldRuleSnapshot := *oldRule

	newRule := *oldRule
	statusChanged := false

	if req.GroupName != nil {
		newRule.GroupName = *req.GroupName
	}
	if req.Description != nil {
		newRule.Description = *req.Description
	}
	if req.Action != nil {
		newRule.Action = *req.Action
	}
	if req.Direction != nil {
		newRule.Direction = *req.Direction
	}
	if req.Protocol != nil {
		newRule.Protocol = *req.Protocol
	}
	if req.IPAddress != nil {
		newRule.IPAddress = *req.IPAddress
	}
	if req.PortStart != nil {
		newRule.PortStart = *req.PortStart
	}
	if req.PortEnd != nil {
		newRule.PortEnd = *req.PortEnd
	}
	if req.Priority != nil {
		newRule.Priority = *req.Priority
	}
	if req.Status != nil {
		newRule.Status = *req.Status
		statusChanged = oldRule.Status != newRule.Status
	}

	if err := validatePortRange(newRule.PortStart, newRule.PortEnd); err != nil {
		return nil, nil, err
	}

	rbInfo := &RollbackInfo{
		Success:       false,
		Rollbacked:    false,
		PreviousState: &oldRuleSnapshot,
	}

	var fwErr error
	var restoredRule *models.SecurityRule

	if statusChanged {
		fwErr = s.fw.ApplyToggleStatusSafe(&newRule)
		if fwErr != nil {
			rbInfo.Rollbacked = strings.Contains(fwErr.Error(), "rollback")
			if rbInfo.Rollbacked {
				newRule = oldRuleSnapshot
				rbInfo.RollbackErrors = extractRollbackErrors(fwErr)
			}
		}
	} else {
		restoredRule, fwErr = s.fw.ApplyUpdateSafe(oldRule, &newRule)
		if fwErr != nil {
			rbInfo.Rollbacked = strings.Contains(fwErr.Error(), "rollback") || restoredRule != nil
			if rbInfo.Rollbacked {
				rbInfo.RollbackErrors = extractRollbackErrors(fwErr)
				if restoredRule != nil {
					newRule = *restoredRule
				} else {
					newRule = oldRuleSnapshot
				}
			}
		}
	}

	if fwErr != nil {
		newRule.ErrorMsg = fwErr.Error()
		if rbInfo.Rollbacked {
			if err := s.repo.Update(&newRule); err != nil {
				rbInfo.RollbackErrors = append(rbInfo.RollbackErrors,
					fmt.Errorf("failed to restore db state after rollback: %w", err))
			}
			return &newRule, rbInfo, fmt.Errorf("%w: %v", ErrRollbackOccurred, fwErr)
		}

		newRule.Status = models.StatusError
		if err := s.repo.Update(&newRule); err != nil {
			return nil, rbInfo, fmt.Errorf("update db failed after fw error: %w (original fw error: %v)", err, fwErr)
		}
		return &newRule, rbInfo, fmt.Errorf("%w: %v", ErrFirewallApply, fwErr)
	}

	newRule.ErrorMsg = ""
	if err := s.repo.Update(&newRule); err != nil {
		return nil, rbInfo, fmt.Errorf("db update failed: %w", err)
	}

	rbInfo.Success = true
	return &newRule, rbInfo, nil
}

func (s *RuleService) DeleteRule(id string) (*RollbackInfo, error) {
	rule, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}

	ruleSnapshot := *rule

	rbInfo := &RollbackInfo{
		Success:       false,
		Rollbacked:    false,
		PreviousState: &ruleSnapshot,
	}

	if err := s.fw.ApplyDeleteSafe(rule); err != nil {
		rbInfo.Rollbacked = strings.Contains(err.Error(), "rollback")
		if rbInfo.Rollbacked {
			rbInfo.RollbackErrors = extractRollbackErrors(err)
		}
		return rbInfo, fmt.Errorf("%w: %v", ErrFirewallApply, err)
	}

	if err := s.repo.Delete(id); err != nil {
		if restoreErr := s.fw.ApplyCreate(&ruleSnapshot); restoreErr != nil {
			rbInfo.RollbackErrors = append(rbInfo.RollbackErrors,
				fmt.Errorf("db delete failed, and failed to restore firewall rule: %w", restoreErr))
			rbInfo.Rollbacked = false
		} else {
			rbInfo.Rollbacked = true
			rbInfo.RollbackErrors = append(rbInfo.RollbackErrors,
				fmt.Errorf("db delete failed, but firewall rule was restored successfully"))
		}
		return rbInfo, fmt.Errorf("db delete failed: %w", err)
	}

	rbInfo.Success = true
	return rbInfo, nil
}

func (s *RuleService) SyncAllRules() (*RollbackInfo, error) {
	rbInfo := &RollbackInfo{
		Success:    false,
		Rollbacked: false,
	}

	err := s.syncAllRulesToFirewall()
	if err != nil {
		rbInfo.Rollbacked = strings.Contains(err.Error(), "rollback")
		if rbInfo.Rollbacked {
			rbInfo.RollbackErrors = extractRollbackErrors(err)
		}
		return rbInfo, fmt.Errorf("sync failed: %w", err)
	}

	rbInfo.Success = true
	return rbInfo, nil
}

func (s *RuleService) syncAllRulesToFirewall() error {
	rules, err := s.repo.ListAllActive()
	if err != nil {
		return fmt.Errorf("load active rules failed: %w", err)
	}

	loadFn := func() ([]models.SecurityRule, error) {
		return s.repo.ListAllActive()
	}

	restoreFn := func(rule *models.SecurityRule) error {
		return s.repo.Update(rule)
	}

	if err := s.fw.SyncAllAtomic(rules, loadFn, restoreFn); err != nil {
		return err
	}

	for i := range rules {
		if err := s.repo.Update(&rules[i]); err != nil {
			return fmt.Errorf("update rule after sync failed: %w", err)
		}
	}

	return nil
}

func (s *RuleService) BatchCreateRules(requests []models.CreateRuleRequest) *BatchResult {
	result := &BatchResult{
		Total: len(requests),
	}

	rm := s.fw.NewRollback()
	createdRules := make([]*models.SecurityRule, 0, len(requests))

	for i, req := range requests {
		if err := validateCreateRequest(&req); err != nil {
			result.Failed++
			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				Message: err.Error(),
			})
			continue
		}

		rule := &models.SecurityRule{
			ID:          uuid.New().String(),
			GroupID:     req.GroupID,
			GroupName:   req.GroupName,
			Description: req.Description,
			Action:      req.Action,
			Direction:   req.Direction,
			Protocol:    req.Protocol,
			IPAddress:   req.IPAddress,
			PortStart:   req.PortStart,
			PortEnd:     req.PortEnd,
			Priority:    req.Priority,
			Status:      models.StatusActive,
		}

		if rule.Direction == "" {
			rule.Direction = models.DirectionInbound
		}
		if rule.Protocol == "" {
			rule.Protocol = models.ProtocolAny
		}
		if rule.Priority == 0 {
			rule.Priority = 100
		}

		if err := s.fw.ApplyCreate(rule); err != nil {
			result.Failed++
			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				RuleID:  rule.ID,
				Message: fmt.Sprintf("firewall error: %v", err),
			})

			rbErrs := rm.Rollback()
			result.Rollbacked = true
			result.RollbackErrs = rbErrs
			result.Failed += result.Success
			result.Success = 0

			for _, cr := range createdRules {
				cr.Status = models.StatusError
				cr.ErrorMsg = "rollback: " + err.Error()
				_ = s.repo.Create(cr)
			}

			return result
		}

		rm.LogAdd(rule)

		if err := s.repo.Create(rule); err != nil {
			_ = s.fw.ApplyDelete(rule)

			rbErrs := rm.Rollback()
			result.Rollbacked = true
			result.RollbackErrs = rbErrs
			result.Failed += result.Success + 1
			result.Success = 0

			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				RuleID:  rule.ID,
				Message: fmt.Sprintf("db error: %v", err),
			})

			return result
		}

		createdRules = append(createdRules, rule)
		result.Success++
	}

	rm.Commit()
	return result
}

func (s *RuleService) BatchUpdateRules(updates []models.BatchUpdateItem) *BatchResult {
	result := &BatchResult{
		Total: len(updates),
	}

	rm := s.fw.NewRollback()
	succeededIDs := make([]string, 0)
	originalRules := make(map[string]*models.SecurityRule)

	for i, update := range updates {
		oldRule, err := s.repo.GetByID(update.ID)
		if err != nil {
			result.Failed++
			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				RuleID:  update.ID,
				Message: fmt.Sprintf("db error: %v", err),
			})
			continue
		}
		if oldRule == nil {
			result.Failed++
			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				RuleID:  update.ID,
				Message: "rule not found",
			})
			continue
		}

		originalRules[update.ID] = oldRule

		newRule := *oldRule
		statusChanged := false

		if update.GroupName != nil {
			newRule.GroupName = *update.GroupName
		}
		if update.Description != nil {
			newRule.Description = *update.Description
		}
		if update.Action != nil {
			newRule.Action = *update.Action
		}
		if update.Direction != nil {
			newRule.Direction = *update.Direction
		}
		if update.Protocol != nil {
			newRule.Protocol = *update.Protocol
		}
		if update.IPAddress != nil {
			newRule.IPAddress = *update.IPAddress
		}
		if update.PortStart != nil {
			newRule.PortStart = *update.PortStart
		}
		if update.PortEnd != nil {
			newRule.PortEnd = *update.PortEnd
		}
		if update.Priority != nil {
			newRule.Priority = *update.Priority
		}
		if update.Status != nil {
			newRule.Status = *update.Status
			statusChanged = oldRule.Status != newRule.Status
		}

		if err := validatePortRange(newRule.PortStart, newRule.PortEnd); err != nil {
			result.Failed++
			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				RuleID:  update.ID,
				Message: err.Error(),
			})
			continue
		}

		var fwErr error
		if statusChanged {
			fwErr = s.fw.ApplyToggleStatusSafe(&newRule)
		} else {
			_, fwErr = s.fw.ApplyUpdateSafe(oldRule, &newRule)
		}

		if fwErr != nil {
			result.Failed++
			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				RuleID:  update.ID,
				Message: fmt.Sprintf("firewall error: %v", fwErr),
			})

			rbErrs := rm.Rollback()
			result.Rollbacked = true
			result.RollbackErrs = rbErrs
			result.Failed += result.Success
			result.Success = 0

			for _, id := range succeededIDs {
				if orig, ok := originalRules[id]; ok {
					_ = s.repo.Update(orig)
				}
			}

			return result
		}

		if firewall.HasFirewallChanges(oldRule, &newRule) || statusChanged {
			rm.LogUpdate(oldRule, &newRule)
		}

		if err := s.repo.Update(&newRule); err != nil {
			rbErrs := rm.Rollback()
			result.Rollbacked = true
			result.RollbackErrs = rbErrs
			result.Failed += result.Success + 1
			result.Success = 0

			result.FailedItems = append(result.FailedItems, BatchFailedItem{
				Index:   i,
				RuleID:  update.ID,
				Message: fmt.Sprintf("db error: %v", err),
			})

			for _, id := range succeededIDs {
				if orig, ok := originalRules[id]; ok {
					_ = s.repo.Update(orig)
				}
			}

			return result
		}

		succeededIDs = append(succeededIDs, update.ID)
		result.Success++
	}

	rm.Commit()
	return result
}

func validateCreateRequest(req *models.CreateRuleRequest) error {
	if req.GroupID == "" {
		return fmt.Errorf("%w: group_id is required", ErrInvalidInput)
	}
	if req.Action == "" {
		return fmt.Errorf("%w: action is required", ErrInvalidInput)
	}
	if req.IPAddress == "" {
		return fmt.Errorf("%w: ip_address is required", ErrInvalidInput)
	}
	if err := validatePortRange(req.PortStart, req.PortEnd); err != nil {
		return err
	}
	return nil
}

func validatePortRange(portStart, portEnd int) error {
	if portStart < 0 || portEnd < 0 {
		return fmt.Errorf("%w: port cannot be negative", ErrInvalidInput)
	}
	if portEnd > 0 && portStart <= 0 {
		return fmt.Errorf("%w: port_start must be set when port_end is set", ErrInvalidInput)
	}
	if portStart > 0 && portEnd > 0 && portEnd < portStart {
		return fmt.Errorf("%w: port_end must be >= port_start", ErrInvalidInput)
	}
	return nil
}

func extractRollbackErrors(err error) []error {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	var errs []error

	if idx := strings.Index(errStr, "rollback errors: ["); idx >= 0 {
		rest := errStr[idx+len("rollback errors: ["):]
		if endIdx := strings.Index(rest, "]"); endIdx >= 0 {
			parts := strings.Split(rest[:endIdx], ", ")
			for _, p := range parts {
				errs = append(errs, errors.New(strings.TrimSpace(p)))
			}
		}
	}

	if len(errs) == 0 && strings.Contains(errStr, "rollback") {
		errs = append(errs, errors.New("rollback executed"))
	}

	return errs
}
