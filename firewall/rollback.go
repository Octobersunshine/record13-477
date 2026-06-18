package firewall

import (
	"fmt"
	"securitygroup/models"
	"sync"
)

type OperationType string

const (
	OpAdd    OperationType = "add"
	OpDelete OperationType = "delete"
	OpUpdate OperationType = "update"
)

type RollbackEntry struct {
	OpType    OperationType
	Rule      *models.SecurityRule
	PrevRule  *models.SecurityRule
	Applied   bool
	Reverted  bool
}

type RollbackManager struct {
	mu       sync.Mutex
	entries  []RollbackEntry
	backend  FirewallBackend
}

func NewRollbackManager(backend FirewallBackend) *RollbackManager {
	return &RollbackManager{
		backend: backend,
		entries: make([]RollbackEntry, 0),
	}
}

func (rm *RollbackManager) LogAdd(rule *models.SecurityRule) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.entries = append(rm.entries, RollbackEntry{
		OpType:  OpAdd,
		Rule:    copyRule(rule),
		Applied: true,
	})
}

func (rm *RollbackManager) LogDelete(rule *models.SecurityRule) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.entries = append(rm.entries, RollbackEntry{
		OpType:  OpDelete,
		Rule:    copyRule(rule),
		Applied: true,
	})
}

func (rm *RollbackManager) LogUpdate(oldRule *models.SecurityRule, newRule *models.SecurityRule) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.entries = append(rm.entries, RollbackEntry{
		OpType:   OpUpdate,
		Rule:     copyRule(newRule),
		PrevRule: copyRule(oldRule),
		Applied:  true,
	})
}

func (rm *RollbackManager) Rollback() []error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var errs []error

	for i := len(rm.entries) - 1; i >= 0; i-- {
		entry := &rm.entries[i]
		if !entry.Applied || entry.Reverted {
			continue
		}

		var err error
		switch entry.OpType {
		case OpAdd:
			err = rm.rollbackAdd(entry)
		case OpDelete:
			err = rm.rollbackDelete(entry)
		case OpUpdate:
			err = rm.rollbackUpdate(entry)
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("rollback op %s for rule %s failed: %w",
				entry.OpType, entry.Rule.ID, err))
		} else {
			entry.Reverted = true
		}
	}

	return errs
}

func (rm *RollbackManager) rollbackAdd(entry *RollbackEntry) error {
	if entry.Rule.FirewallID != "" {
		return rm.backend.DeleteRule(entry.Rule)
	}
	return nil
}

func (rm *RollbackManager) rollbackDelete(entry *RollbackEntry) error {
	if entry.Rule.Status == models.StatusActive {
		fwID, err := rm.backend.AddRule(entry.Rule)
		if err == nil {
			entry.Rule.FirewallID = fwID
		}
		return err
	}
	return nil
}

func (rm *RollbackManager) rollbackUpdate(entry *RollbackEntry) error {
	if entry.PrevRule == nil {
		return nil
	}

	prev := entry.PrevRule
	curr := entry.Rule

	if curr.FirewallID != "" {
		if err := rm.backend.DeleteRule(curr); err != nil {
			return err
		}
	}

	if prev.Status == models.StatusActive {
		fwID, err := rm.backend.AddRule(prev)
		if err == nil {
			prev.FirewallID = fwID
			entry.Rule.FirewallID = fwID
		}
		return err
	}

	return nil
}

func (rm *RollbackManager) Reset() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.entries = make([]RollbackEntry, 0)
}

func (rm *RollbackManager) Commit() {
	rm.Reset()
}

func (rm *RollbackManager) HasEntries() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return len(rm.entries) > 0
}

func copyRule(r *models.SecurityRule) *models.SecurityRule {
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}
