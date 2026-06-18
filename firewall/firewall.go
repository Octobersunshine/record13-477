package firewall

import (
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

func NewManager(backend FirewallBackend) *Manager {
	return &Manager{backend: backend}
}

func (m *Manager) BackendName() string {
	return m.backend.Name()
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

func (m *Manager) ApplyDelete(rule *models.SecurityRule) error {
	if rule.Status == models.StatusActive && rule.FirewallID != "" {
		return m.backend.DeleteRule(rule)
	}
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

func (m *Manager) SyncAll(rules []models.SecurityRule) error {
	return m.backend.SyncRules(rules)
}

func hasFirewallChanges(old *models.SecurityRule, new *models.SecurityRule) bool {
	return old.Action != new.Action ||
		old.Direction != new.Direction ||
		old.Protocol != new.Protocol ||
		old.IPAddress != new.IPAddress ||
		old.PortStart != new.PortStart ||
		old.PortEnd != new.PortEnd
}
