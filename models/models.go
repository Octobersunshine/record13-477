package models

import (
	"time"

	"gorm.io/gorm"
)

type RuleAction string

const (
	ActionAllow RuleAction = "allow"
	ActionDeny  RuleAction = "deny"
)

type RuleDirection string

const (
	DirectionInbound  RuleDirection = "inbound"
	DirectionOutbound RuleDirection = "outbound"
)

type RuleProtocol string

const (
	ProtocolTCP RuleProtocol = "TCP"
	ProtocolUDP RuleProtocol = "UDP"
	ProtocolAny RuleProtocol = "ANY"
)

type RuleStatus string

const (
	StatusActive   RuleStatus = "active"
	StatusDisabled RuleStatus = "disabled"
	StatusError    RuleStatus = "error"
)

type SecurityRule struct {
	ID          string         `gorm:"primaryKey;type:varchar(36)" json:"id"`
	GroupID     string         `gorm:"index;type:varchar(64);not null" json:"group_id" binding:"required"`
	GroupName   string         `gorm:"type:varchar(128)" json:"group_name"`
	Description string         `gorm:"type:varchar(256)" json:"description"`
	Action      RuleAction     `gorm:"type:varchar(16);not null" json:"action" binding:"required,oneof=allow deny"`
	Direction   RuleDirection  `gorm:"type:varchar(16);not null;default:inbound" json:"direction" binding:"oneof=inbound outbound"`
	Protocol    RuleProtocol   `gorm:"type:varchar(8);not null;default:ANY" json:"protocol" binding:"oneof=TCP UDP ANY"`
	IPAddress   string         `gorm:"type:varchar(64);not null" json:"ip_address" binding:"required,ip|cidr"`
	PortStart   int            `gorm:"default:0" json:"port_start" binding:"omitempty,min=1,max=65535"`
	PortEnd     int            `gorm:"default:0" json:"port_end" binding:"omitempty,min=1,max=65535"`
	Priority    int            `gorm:"default:100" json:"priority" binding:"min=1,max=10000"`
	Status      RuleStatus     `gorm:"type:varchar(16);default:active" json:"status"`
	FirewallID  string         `gorm:"type:varchar(128)" json:"firewall_id,omitempty"`
	ErrorMsg    string         `gorm:"type:varchar(512)" json:"error_msg,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

type CreateRuleRequest struct {
	GroupID     string        `json:"group_id" binding:"required"`
	GroupName   string        `json:"group_name"`
	Description string        `json:"description"`
	Action      RuleAction    `json:"action" binding:"required,oneof=allow deny"`
	Direction   RuleDirection `json:"direction" binding:"oneof=inbound outbound"`
	Protocol    RuleProtocol  `json:"protocol" binding:"oneof=TCP UDP ANY"`
	IPAddress   string        `json:"ip_address" binding:"required,ip|cidr"`
	PortStart   int           `json:"port_start" binding:"omitempty,min=1,max=65535"`
	PortEnd     int           `json:"port_end" binding:"omitempty,min=1,max=65535"`
	Priority    int           `json:"priority" binding:"min=1,max=10000"`
}

type UpdateRuleRequest struct {
	GroupName   *string        `json:"group_name"`
	Description *string        `json:"description"`
	Action      *RuleAction    `json:"action" binding:"omitempty,oneof=allow deny"`
	Direction   *RuleDirection `json:"direction" binding:"omitempty,oneof=inbound outbound"`
	Protocol    *RuleProtocol  `json:"protocol" binding:"omitempty,oneof=TCP UDP ANY"`
	IPAddress   *string        `json:"ip_address" binding:"omitempty,ip|cidr"`
	PortStart   *int           `json:"port_start" binding:"omitempty,min=1,max=65535"`
	PortEnd     *int           `json:"port_end" binding:"omitempty,min=1,max=65535"`
	Priority    *int           `json:"priority" binding:"omitempty,min=1,max=10000"`
	Status      *RuleStatus    `json:"status" binding:"omitempty,oneof=active disabled"`
}

type RuleListResponse struct {
	Total int64          `json:"total"`
	List  []SecurityRule `json:"list"`
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
