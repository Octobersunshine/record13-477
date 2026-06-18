package handlers

import (
	"errors"
	"net/http"
	"securitygroup/models"
	"securitygroup/service"

	"github.com/gin-gonic/gin"
)

type ApprovalHandler struct {
	svc *service.ApprovalService
}

func NewApprovalHandler(svc *service.ApprovalService) *ApprovalHandler {
	return &ApprovalHandler{svc: svc}
}

func (h *ApprovalHandler) CreateApproval(c *gin.Context) {
	var req models.CreateApprovalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40020, "invalid request body: "+err.Error())
		return
	}

	approval, err := h.svc.CreateApproval(&req)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, 50020, "failed to create approval: "+err.Error())
		return
	}

	c.JSON(http.StatusCreated, models.APIResponse{
		Code:    0,
		Message: "approval request created",
		Data:    approval,
	})
}

func (h *ApprovalHandler) GetApproval(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40021, "approval id is required")
		return
	}

	approval, err := h.svc.GetApproval(id)
	if err != nil {
		if errors.Is(err, service.ErrApprovalNotFound) {
			errorResponse(c, http.StatusNotFound, 40420, err.Error())
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50021, "internal error: "+err.Error())
		return
	}

	successResponse(c, approval)
}

func (h *ApprovalHandler) ListApprovals(c *gin.Context) {
	status := c.Query("status")
	operationType := c.Query("operation_type")
	applicant := c.Query("applicant")

	page := parseIntParam(c.Query("page"), 1)
	pageSize := parseIntParam(c.Query("page_size"), 20)

	result, err := h.svc.ListApprovals(status, operationType, applicant, page, pageSize)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, 50022, "internal error: "+err.Error())
		return
	}

	successResponse(c, result)
}

func (h *ApprovalHandler) Approve(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40022, "approval id is required")
		return
	}

	var req models.ApproveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40023, "invalid request body: "+err.Error())
		return
	}

	approval, err := h.svc.Approve(id, req.Approver, req.Remark)
	if err != nil {
		if errors.Is(err, service.ErrApprovalNotFound) {
			errorResponse(c, http.StatusNotFound, 40421, err.Error())
			return
		}
		if errors.Is(err, service.ErrApprovalInvalidState) {
			errorResponse(c, http.StatusConflict, 40920, err.Error())
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50023, "internal error: "+err.Error())
		return
	}

	successResponse(c, approval)
}

func (h *ApprovalHandler) Reject(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40024, "approval id is required")
		return
	}

	var req models.RejectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40025, "invalid request body: "+err.Error())
		return
	}

	approval, err := h.svc.Reject(id, req.Approver, req.Remark)
	if err != nil {
		if errors.Is(err, service.ErrApprovalNotFound) {
			errorResponse(c, http.StatusNotFound, 40422, err.Error())
			return
		}
		if errors.Is(err, service.ErrApprovalInvalidState) {
			errorResponse(c, http.StatusConflict, 40921, err.Error())
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50024, "internal error: "+err.Error())
		return
	}

	successResponse(c, approval)
}

func (h *ApprovalHandler) Execute(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40026, "approval id is required")
		return
	}

	result, rbInfo, err := h.svc.Execute(id)
	if err != nil {
		if errors.Is(err, service.ErrApprovalNotFound) {
			errorResponse(c, http.StatusNotFound, 40423, err.Error())
			return
		}
		if errors.Is(err, service.ErrApprovalInvalidState) {
			errorResponse(c, http.StatusConflict, 40922, err.Error())
			return
		}

		respData := gin.H{
			"success":       false,
			"error_msg":     err.Error(),
			"rollback_info": toRollbackInfoResponse(rbInfo),
			"result":        result,
		}

		if rbInfo != nil && rbInfo.Rollbacked {
			c.JSON(http.StatusConflict, models.APIResponse{
				Code:    40923,
				Message: "Execution failed and rolled back: " + err.Error(),
				Data:    respData,
			})
			return
		}

		c.JSON(http.StatusFailedDependency, models.APIResponse{
			Code:    42420,
			Message: "Execution failed: " + err.Error(),
			Data:    respData,
		})
		return
	}

	successResponse(c, gin.H{
		"success":       true,
		"result":        result,
		"rollback_info": toRollbackInfoResponse(rbInfo),
	})
}

func (h *ApprovalHandler) Cancel(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40027, "approval id is required")
		return
	}

	approval, err := h.svc.Cancel(id)
	if err != nil {
		if errors.Is(err, service.ErrApprovalNotFound) {
			errorResponse(c, http.StatusNotFound, 40424, err.Error())
			return
		}
		if errors.Is(err, service.ErrApprovalInvalidState) {
			errorResponse(c, http.StatusConflict, 40924, err.Error())
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50025, "internal error: "+err.Error())
		return
	}

	successResponse(c, approval)
}

func (h *ApprovalHandler) EvaluateRisk(c *gin.Context) {
	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40028, "invalid request body: "+err.Error())
		return
	}

	risk := service.EvaluateCreateRisk(&req)
	isHigh := service.IsHighRisk(risk)

	successResponse(c, gin.H{
		"risk_level":    risk,
		"is_high_risk":  isHigh,
		"approval_needed": isHigh,
	})
}
