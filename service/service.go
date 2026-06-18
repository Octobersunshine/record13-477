package service

import (
	"errors"
	"fmt"
	"securitygroup/firewall"
	"securitygroup/models"
	"securitygroup/repository"

	"github.com/google/uuid"
)

var (
	ErrRuleNotFound  = errors.New("rule not found")
	ErrInvalidInput  = errors.New("invalid input")
	ErrFirewallApply = errors.New("failed to apply firewall rule")
)

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

func (s *RuleService) UpdateRule(id string, req *models.UpdateRuleRequest) (*models.SecurityRule, error) {
	oldRule, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	if oldRule == nil {
		return nil, ErrRuleNotFound
	}

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
		return nil, err
	}

	if statusChanged {
		if err := s.fw.ApplyToggleStatus(&newRule); err != nil {
			newRule.Status = models.StatusError
			newRule.ErrorMsg = err.Error()
			if saveErr := s.repo.Update(&newRule); saveErr != nil {
				return nil, fmt.Errorf("update db failed after fw error: %w (original fw error: %v)", saveErr, err)
			}
			return &newRule, fmt.Errorf("%w: %v", ErrFirewallApply, err)
		}
	} else {
		if err := s.fw.ApplyUpdate(oldRule, &newRule); err != nil {
			newRule.Status = models.StatusError
			newRule.ErrorMsg = err.Error()
			if saveErr := s.repo.Update(&newRule); saveErr != nil {
				return nil, fmt.Errorf("update db failed after fw error: %w (original fw error: %v)", saveErr, err)
			}
			return &newRule, fmt.Errorf("%w: %v", ErrFirewallApply, err)
		}
	}

	newRule.ErrorMsg = ""
	if err := s.repo.Update(&newRule); err != nil {
		return nil, fmt.Errorf("db update failed: %w", err)
	}

	return &newRule, nil
}

func (s *RuleService) DeleteRule(id string) error {
	rule, err := s.repo.GetByID(id)
	if err != nil {
		return err
	}
	if rule == nil {
		return ErrRuleNotFound
	}

	if err := s.fw.ApplyDelete(rule); err != nil {
		return fmt.Errorf("%w: %v", ErrFirewallApply, err)
	}

	if err := s.repo.Delete(id); err != nil {
		return fmt.Errorf("db delete failed: %w", err)
	}

	return nil
}

func (s *RuleService) SyncAllRules() error {
	return s.syncAllRulesToFirewall()
}

func (s *RuleService) syncAllRulesToFirewall() error {
	rules, err := s.repo.ListAllActive()
	if err != nil {
		return fmt.Errorf("load active rules failed: %w", err)
	}

	if err := s.fw.SyncAll(rules); err != nil {
		return err
	}

	for i := range rules {
		if err := s.repo.Update(&rules[i]); err != nil {
			return fmt.Errorf("update rule after sync failed: %w", err)
		}
	}

	return nil
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
