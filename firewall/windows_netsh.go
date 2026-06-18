package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"securitygroup/models"
	"strings"
	"sync"
)

type WindowsNetshBackend struct {
	rulePrefix string
	mu         sync.Mutex
}

func NewWindowsNetshBackend() *WindowsNetshBackend {
	return &WindowsNetshBackend{
		rulePrefix: "SG_",
	}
}

func (b *WindowsNetshBackend) Name() string {
	return "windows-netsh"
}

func (b *WindowsNetshBackend) AddRule(rule *models.SecurityRule) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("netsh backend only supported on Windows")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	ruleName := b.buildRuleName(rule)
	args := b.buildAddRuleArgs(ruleName, rule)

	cmd := exec.Command("netsh", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("netsh add rule failed: %w, stderr: %s", err, stderr.String())
	}

	return ruleName, nil
}

func (b *WindowsNetshBackend) UpdateRule(oldRule *models.SecurityRule, newRule *models.SecurityRule) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("netsh backend only supported on Windows")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	oldRuleName := oldRule.FirewallID
	if oldRuleName == "" {
		oldRuleName = b.buildRuleName(oldRule)
	}

	if err := b.deleteRuleByName(oldRuleName); err != nil {
		return "", err
	}

	newRuleName := b.buildRuleName(newRule)
	args := b.buildAddRuleArgs(newRuleName, newRule)

	cmd := exec.Command("netsh", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("netsh update rule failed: %w, stderr: %s", err, stderr.String())
	}

	return newRuleName, nil
}

func (b *WindowsNetshBackend) DeleteRule(rule *models.SecurityRule) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("netsh backend only supported on Windows")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	ruleName := rule.FirewallID
	if ruleName == "" {
		ruleName = b.buildRuleName(rule)
	}

	return b.deleteRuleByName(ruleName)
}

func (b *WindowsNetshBackend) EnableRule(rule *models.SecurityRule) (string, error) {
	return b.AddRule(rule)
}

func (b *WindowsNetshBackend) DisableRule(rule *models.SecurityRule) error {
	return b.DeleteRule(rule)
}

func (b *WindowsNetshBackend) SyncRules(rules []models.SecurityRule) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("netsh backend only supported on Windows")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.cleanupManagedRules(); err != nil {
		return fmt.Errorf("cleanup old rules failed: %w", err)
	}

	for i := range rules {
		rule := &rules[i]
		if rule.Status != models.StatusActive {
			continue
		}
		ruleName := b.buildRuleName(rule)
		args := b.buildAddRuleArgs(ruleName, rule)

		cmd := exec.Command("netsh", args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("sync: failed to add rule %s: %w, stderr: %s", rule.ID, err, stderr.String())
		}
		rule.FirewallID = ruleName
	}

	return nil
}

func (b *WindowsNetshBackend) buildRuleName(rule *models.SecurityRule) string {
	return fmt.Sprintf("%s%s_%s", b.rulePrefix, rule.GroupID, rule.ID[:8])
}

func (b *WindowsNetshBackend) buildAddRuleArgs(ruleName string, rule *models.SecurityRule) []string {
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
	}

	switch rule.Action {
	case models.ActionAllow:
		args = append(args, "action=allow")
	case models.ActionDeny:
		args = append(args, "action=block")
	}

	switch rule.Direction {
	case models.DirectionInbound:
		args = append(args, "dir=in")
	case models.DirectionOutbound:
		args = append(args, "dir=out")
	}

	if rule.Protocol != models.ProtocolAny {
		args = append(args, fmt.Sprintf("protocol=%s", strings.ToLower(string(rule.Protocol))))
	}

	args = append(args, fmt.Sprintf("remoteip=%s", rule.IPAddress))

	if rule.PortStart > 0 {
		if rule.PortEnd > rule.PortStart {
			args = append(args, fmt.Sprintf("localport=%d-%d", rule.PortStart, rule.PortEnd))
		} else {
			args = append(args, fmt.Sprintf("localport=%d", rule.PortStart))
		}
	}

	args = append(args, "enable=yes")

	if rule.Description != "" {
		desc := truncateString(rule.Description, 255)
		args = append(args, fmt.Sprintf("description=%s", desc))
	}

	return args
}

func (b *WindowsNetshBackend) deleteRuleByName(ruleName string) error {
	args := []string{
		"advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName),
	}

	cmd := exec.Command("netsh", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "No rule") || strings.Contains(errStr, "没有") ||
			strings.Contains(errStr, "找不到") {
			return nil
		}
		return fmt.Errorf("netsh delete rule failed: %w, stderr: %s", err, errStr)
	}

	return nil
}

func (b *WindowsNetshBackend) cleanupManagedRules() error {
	args := []string{
		"advfirewall", "firewall", "show", "rules",
		"name=all", "verbose",
	}

	cmd := exec.Command("netsh", args...)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("netsh show rules failed: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Rule Name:") {
			ruleName := strings.TrimSpace(strings.TrimPrefix(line, "Rule Name:"))
			if strings.HasPrefix(ruleName, b.rulePrefix) {
				_ = b.deleteRuleByName(ruleName)
			}
		}
	}

	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
