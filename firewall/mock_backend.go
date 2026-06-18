package firewall

import (
	"fmt"
	"securitygroup/models"
	"sync"
)

type MockBackend struct {
	mu    sync.Mutex
	rules map[string]models.SecurityRule
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		rules: make(map[string]models.SecurityRule),
	}
}

func (b *MockBackend) Name() string {
	return "mock"
}

func (b *MockBackend) AddRule(rule *models.SecurityRule) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	fwID := fmt.Sprintf("mock-fw-%s", rule.ID)
	b.rules[fwID] = *rule
	return fwID, nil
}

func (b *MockBackend) UpdateRule(oldRule *models.SecurityRule, newRule *models.SecurityRule) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	oldFwID := oldRule.FirewallID
	if oldFwID != "" {
		delete(b.rules, oldFwID)
	}

	newFwID := fmt.Sprintf("mock-fw-%s", newRule.ID)
	b.rules[newFwID] = *newRule
	return newFwID, nil
}

func (b *MockBackend) DeleteRule(rule *models.SecurityRule) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	fwID := rule.FirewallID
	if fwID != "" {
		delete(b.rules, fwID)
	} else {
		for id, r := range b.rules {
			if r.ID == rule.ID {
				delete(b.rules, id)
				break
			}
		}
	}
	return nil
}

func (b *MockBackend) EnableRule(rule *models.SecurityRule) (string, error) {
	return b.AddRule(rule)
}

func (b *MockBackend) DisableRule(rule *models.SecurityRule) error {
	return b.DeleteRule(rule)
}

func (b *MockBackend) SyncRules(rules []models.SecurityRule) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.rules = make(map[string]models.SecurityRule)
	for i := range rules {
		rule := rules[i]
		if rule.Status != models.StatusActive {
			continue
		}
		fwID := fmt.Sprintf("mock-fw-%s", rule.ID)
		b.rules[fwID] = rule
		rules[i].FirewallID = fwID
	}
	return nil
}

func (b *MockBackend) GetActiveRuleCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.rules)
}

func (b *MockBackend) HasRule(fwID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.rules[fwID]
	return ok
}
