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

type BatchUpdateItem struct {
	ID          string         `json:"id" binding:"required"`
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

type BatchCreateRequest struct {
	Rules []CreateRuleRequest `json:"rules" binding:"required,min=1,dive"`
}

type BatchUpdateRequest struct {
	Rules []BatchUpdateItem `json:"rules" binding:"required,min=1,dive"`
}

type RollbackInfoResponse struct {
	Success        bool        `json:"success"`
	Rollbacked     bool        `json:"rollbacked"`
	RollbackErrors []string    `json:"rollback_errors,omitempty"`
	PreviousState  interface{} `json:"previous_state,omitempty"`
}

type BatchResultResponse struct {
	Success      int                      `json:"success"`
	Failed       int                      `json:"failed"`
	Total        int                      `json:"total"`
	FailedItems  []BatchFailedItemResponse `json:"failed_items,omitempty"`
	Rollbacked   bool                     `json:"rollbacked"`
	RollbackErrs []string                 `json:"rollback_errors,omitempty"`
}

type BatchFailedItemResponse struct {
	Index   int    `json:"index"`
	RuleID  string `json:"rule_id,omitempty"`
	Message string `json:"message"`
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ApprovalStatus string

const (
	ApprovalPending   ApprovalStatus = "pending"
	ApprovalApproved  ApprovalStatus = "approved"
	ApprovalRejected  ApprovalStatus = "rejected"
	ApprovalExecuted  ApprovalStatus = "executed"
	ApprovalCancelled ApprovalStatus = "cancelled"
	ApprovalFailed    ApprovalStatus = "failed"
)

type ApprovalOperationType string

const (
	ApprovalOpCreate    ApprovalOperationType = "create"
	ApprovalOpUpdate    ApprovalOperationType = "update"
	ApprovalOpDelete    ApprovalOperationType = "delete"
	ApprovalOpBatchCreate ApprovalOperationType = "batch_create"
	ApprovalOpBatchUpdate ApprovalOperationType = "batch_update"
	ApprovalOpSync      ApprovalOperationType = "sync"
)

type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

type ApprovalRequest struct {
	ID            string              `gorm:"primaryKey;type:varchar(36)" json:"id"`
	Title         string              `gorm:"type:varchar(256);not null" json:"title"`
	Description   string              `gorm:"type:varchar(512)" json:"description"`
	OperationType ApprovalOperationType `gorm:"type:varchar(32);not null" json:"operation_type"`
	RiskLevel     RiskLevel           `gorm:"type:varchar(16);not null" json:"risk_level"`
	Status        ApprovalStatus      `gorm:"type:varchar(16);not null;default:pending" json:"status"`
	Applicant     string              `gorm:"type:varchar(64);not null" json:"applicant"`
	Approver      string              `gorm:"type:varchar(64)" json:"approver,omitempty"`
	ApprovalRemark string             `gorm:"type:varchar(512)" json:"approval_remark,omitempty"`
	RuleID        string              `gorm:"type:varchar(36)" json:"rule_id,omitempty"`
	RuleSnapshot  string              `gorm:"type:text" json:"rule_snapshot,omitempty"`
	NewRuleData   string              `gorm:"type:text" json:"new_rule_data,omitempty"`
	ErrorMsg      string              `gorm:"type:varchar(512)" json:"error_msg,omitempty"`
	SubmittedAt   *time.Time          `json:"submitted_at,omitempty"`
	ApprovedAt    *time.Time          `json:"approved_at,omitempty"`
	ExecutedAt    *time.Time          `json:"executed_at,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
	DeletedAt     gorm.DeletedAt      `gorm:"index" json:"deleted_at,omitempty"`
}

type ApprovalListResponse struct {
	Total int64             `json:"total"`
	List  []ApprovalRequest `json:"list"`
}

type CreateApprovalRequest struct {
	Title         string                `json:"title" binding:"required"`
	Description   string                `json:"description"`
	OperationType ApprovalOperationType `json:"operation_type" binding:"required,oneof=create update delete batch_create batch_update sync"`
	RuleID        string                `json:"rule_id"`
	NewRuleData   string                `json:"new_rule_data"`
	Applicant     string                `json:"applicant" binding:"required"`
}

type ApproveRequest struct {
	Approver string `json:"approver" binding:"required"`
	Remark   string `json:"remark"`
}

type RejectRequest struct {
	Approver string `json:"approver" binding:"required"`
	Remark   string `json:"remark" binding:"required"`
}

type ExecuteApprovalResponse struct {
	Success       bool                   `json:"success"`
	RollbackInfo  *RollbackInfoResponse  `json:"rollback_info,omitempty"`
	Result        interface{}            `json:"result,omitempty"`
	ErrorMsg      string                 `json:"error_msg,omitempty"`
}
