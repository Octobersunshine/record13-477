package firewall

import (
	"fmt"
	"securitygroup/models"
)

type FirewallBackend interface {
	AddRule(rule *models.SecurityRule) (string, error)
	UpdateRule(oldRule *models.SecurityRule, newRule *models.SecurityRule) (string, error)
	DeleteRule(rule *models.SecurityRule) error
	EnableRule(rule *models.SecurityRule) (string, error)
	DisableRule(rule *models.SecurityRule) error
	SyncRules(rules []models.SecurityRule) error
	Name() string
}

type Manager struct {
	backend FirewallBackend
}

type SafeUpdateResult struct {
	Success    bool
	Rollbacked bool
	Rule       *models.SecurityRule
	Error      error
}

func NewManager(backend FirewallBackend) *Manager {
	return &Manager{backend: backend}
}

func (m *Manager) BackendName() string {
	return m.backend.Name()
}

func (m *Manager) NewRollback() *RollbackManager {
	return NewRollbackManager(m.backend)
}

func (m *Manager) ApplyCreate(rule *models.SecurityRule) error {
	if rule.Status != models.StatusActive {
		return nil
	}
	fwID, err := m.backend.AddRule(rule)
	if err != nil {
		return err
	}
	rule.FirewallID = fwID
	return nil
}

func (m *Manager) ApplyCreateSafe(rule *models.SecurityRule) error {
	rm := m.NewRollback()
	return m.applyCreateWithRollback(rule, rm)
}

func (m *Manager) applyCreateWithRollback(rule *models.SecurityRule, rm *RollbackManager) error {
	if rule.Status != models.StatusActive {
		return nil
	}

	fwID, err := m.backend.AddRule(rule)
	if err != nil {
		return err
	}

	oldFirewallID := rule.FirewallID
	rule.FirewallID = fwID
	rm.LogAdd(rule)

	_ = oldFirewallID
	return nil
}

func (m *Manager) ApplyUpdate(oldRule *models.SecurityRule, newRule *models.SecurityRule) error {
	wasActive := oldRule.Status == models.StatusActive
	willBeActive := newRule.Status == models.StatusActive

	switch {
	case !wasActive && willBeActive:
		fwID, err := m.backend.AddRule(newRule)
		if err != nil {
			return err
		}
		newRule.FirewallID = fwID
	case wasActive && !willBeActive:
		if oldRule.FirewallID != "" {
			if err := m.backend.DisableRule(oldRule); err != nil {
				return err
			}
		}
		newRule.FirewallID = ""
	case wasActive && willBeActive:
		changed := hasFirewallChanges(oldRule, newRule)
		if changed {
			if oldRule.FirewallID != "" {
				if err := m.backend.DeleteRule(oldRule); err != nil {
					return err
				}
			}
			fwID, err := m.backend.AddRule(newRule)
			if err != nil {
				return err
			}
			newRule.FirewallID = fwID
		}
	}
	return nil
}

func (m *Manager) ApplyUpdateSafe(oldRule *models.SecurityRule, newRule *models.SecurityRule) (*models.SecurityRule, error) {
	rm := m.NewRollback()
	return m.applyUpdateWithRollback(oldRule, newRule, rm)
}

func (m *Manager) applyUpdateWithRollback(oldRule *models.SecurityRule, newRule *models.SecurityRule, rm *RollbackManager) (*models.SecurityRule, error) {
	wasActive := oldRule.Status == models.StatusActive
	willBeActive := newRule.Status == models.StatusActive

	newRuleSnapshot := *newRule

	switch {
	case !wasActive && willBeActive:
		fwID, err := m.backend.AddRule(newRule)
		if err != nil {
			return nil, err
		}
		newRule.FirewallID = fwID
		rm.LogAdd(newRule)

	case wasActive && !willBeActive:
		if oldRule.FirewallID != "" {
			rm.LogDelete(oldRule)
			if err := m.backend.DisableRule(oldRule); err != nil {
				rbErrs := rm.Rollback()
				if len(rbErrs) > 0 {
					return nil, fmt.Errorf("update failed: %w, rollback errors: %v", err, rbErrs)
				}
				return nil, err
			}
		}
		newRule.FirewallID = ""

	case wasActive && willBeActive:
		changed := hasFirewallChanges(oldRule, newRule)
		if changed {
			rm.LogUpdate(oldRule, newRule)

			if oldRule.FirewallID != "" {
				if err := m.backend.DeleteRule(oldRule); err != nil {
					rbErrs := rm.Rollback()
					if len(rbErrs) > 0 {
						return nil, fmt.Errorf("delete old rule failed: %w, rollback errors: %v", err, rbErrs)
					}
					return nil, err
				}
			}

			fwID, err := m.backend.AddRule(newRule)
			if err != nil {
				rbErrs := rm.Rollback()
				if len(rbErrs) > 0 {
					return &newRuleSnapshot, fmt.Errorf("add new rule failed: %w, rollback errors: %v", err, rbErrs)
				}
				restored := *oldRule
				return &restored, err
			}
			newRule.FirewallID = fwID
		}
	}

	rm.Commit()
	return newRule, nil
}

func (m *Manager) ApplyDelete(rule *models.SecurityRule) error {
	if rule.Status == models.StatusActive && rule.FirewallID != "" {
		return m.backend.DeleteRule(rule)
	}
	return nil
}

func (m *Manager) ApplyDeleteSafe(rule *models.SecurityRule) error {
	rm := m.NewRollback()
	return m.applyDeleteWithRollback(rule, rm)
}

func (m *Manager) applyDeleteWithRollback(rule *models.SecurityRule, rm *RollbackManager) error {
	if rule.Status == models.StatusActive && rule.FirewallID != "" {
		rm.LogDelete(rule)
		if err := m.backend.DeleteRule(rule); err != nil {
			rbErrs := rm.Rollback()
			if len(rbErrs) > 0 {
				return fmt.Errorf("delete failed: %w, rollback errors: %v", err, rbErrs)
			}
			return err
		}
	}
	rm.Commit()
	return nil
}

func (m *Manager) ApplyToggleStatus(rule *models.SecurityRule) error {
	if rule.Status == models.StatusActive {
		fwID, err := m.backend.EnableRule(rule)
		if err != nil {
			return err
		}
		rule.FirewallID = fwID
	} else {
		if rule.FirewallID != "" {
			if err := m.backend.DisableRule(rule); err != nil {
				return err
			}
		}
		rule.FirewallID = ""
	}
	return nil
}

func (m *Manager) ApplyToggleStatusSafe(rule *models.SecurityRule) error {
	rm := m.NewRollback()

	if rule.Status == models.StatusActive {
		fwID, err := m.backend.EnableRule(rule)
		if err != nil {
			return err
		}
		rule.FirewallID = fwID
		rm.LogAdd(rule)
	} else {
		if rule.FirewallID != "" {
			ruleCopy := *rule
			ruleCopy.Status = models.StatusActive
			rm.LogDelete(&ruleCopy)

			if err := m.backend.DisableRule(rule); err != nil {
				rbErrs := rm.Rollback()
				if len(rbErrs) > 0 {
					return fmt.Errorf("disable failed: %w, rollback errors: %v", err, rbErrs)
				}
				return err
			}
			rule.FirewallID = ""
		}
	}

	rm.Commit()
	return nil
}

func (m *Manager) SyncAll(rules []models.SecurityRule) error {
	return m.backend.SyncRules(rules)
}

func (m *Manager) SyncAllSafe(rules []models.SecurityRule) error {
	return m.backend.SyncRules(rules)
}

func (m *Manager) SyncAllAtomic(desiredRules []models.SecurityRule, loadActiveFn func() ([]models.SecurityRule, error), restoreFn func(rule *models.SecurityRule) error) error {
	rm := m.NewRollback()

	originalRules, err := loadActiveFn()
	if err != nil {
		return fmt.Errorf("failed to load original rules for snapshot: %w", err)
	}

	for i := range originalRules {
		rm.LogDelete(&originalRules[i])
	}

	for i := range desiredRules {
		if desiredRules[i].Status != models.StatusActive {
			continue
		}
		rule := &desiredRules[i]
		fwID, err := m.backend.AddRule(rule)
		if err != nil {
			rbErrs := rm.Rollback()

			for _, r := range originalRules {
				if r.Status == models.StatusActive {
					_ = restoreFn(&r)
				}
			}

			if len(rbErrs) > 0 {
				return fmt.Errorf("sync failed at rule %d: %w, rollback errors: %v", i, err, rbErrs)
			}
			return fmt.Errorf("sync failed at rule %d: %w, rollback completed successfully", i, err)
		}
		rule.FirewallID = fwID
		rm.LogAdd(rule)
	}

	if err := m.cleanupOldRules(originalRules, desiredRules); err != nil {
		rbErrs := rm.Rollback()

		for _, r := range originalRules {
			if r.Status == models.StatusActive {
				_ = restoreFn(&r)
			}
		}

		if len(rbErrs) > 0 {
			return fmt.Errorf("cleanup failed: %w, rollback errors: %v", err, rbErrs)
		}
		return fmt.Errorf("cleanup failed: %w, rollback completed successfully", err)
	}

	rm.Commit()
	return nil
}

func (m *Manager) cleanupOldRules(original []models.SecurityRule, desired []models.SecurityRule) error {
	desiredIDs := make(map[string]bool)
	for _, r := range desired {
		if r.Status == models.StatusActive && r.FirewallID != "" {
			desiredIDs[r.FirewallID] = true
		}
	}

	for _, r := range original {
		if r.FirewallID != "" && !desiredIDs[r.FirewallID] {
			if err := m.backend.DeleteRule(&r); err != nil {
				return fmt.Errorf("failed to delete old rule %s: %w", r.ID, err)
			}
		}
	}

	return nil
}

func hasFirewallChanges(old *models.SecurityRule, new *models.SecurityRule) bool {
	return old.Action != new.Action ||
		old.Direction != new.Direction ||
		old.Protocol != new.Protocol ||
		old.IPAddress != new.IPAddress ||
		old.PortStart != new.PortStart ||
		old.PortEnd != new.PortEnd
}
