package handlers

import (
	"errors"
	"net/http"
	"securitygroup/models"
	"securitygroup/service"
	"strconv"

	"github.com/gin-gonic/gin"
)

type RuleHandler struct {
	svc *service.RuleService
}

func NewRuleHandler(svc *service.RuleService) *RuleHandler {
	return &RuleHandler{svc: svc}
}

func successResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, models.APIResponse{
		Code:    0,
		Message: "success",
		Data:    data,
	})
}

func createdResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, models.APIResponse{
		Code:    0,
		Message: "created",
		Data:    data,
	})
}

func errorResponse(c *gin.Context, httpStatus int, code int, message string) {
	c.JSON(httpStatus, models.APIResponse{
		Code:    code,
		Message: message,
	})
}

func toRollbackInfoResponse(rb *service.RollbackInfo) *models.RollbackInfoResponse {
	if rb == nil {
		return nil
	}
	resp := &models.RollbackInfoResponse{
		Success:       rb.Success,
		Rollbacked:    rb.Rollbacked,
		PreviousState: rb.PreviousState,
	}
	for _, e := range rb.RollbackErrors {
		resp.RollbackErrors = append(resp.RollbackErrors, e.Error())
	}
	return resp
}

func toBatchResultResponse(br *service.BatchResult) *models.BatchResultResponse {
	if br == nil {
		return nil
	}
	resp := &models.BatchResultResponse{
		Success:    br.Success,
		Failed:     br.Failed,
		Total:      br.Total,
		Rollbacked: br.Rollbacked,
	}
	for _, item := range br.FailedItems {
		resp.FailedItems = append(resp.FailedItems, models.BatchFailedItemResponse{
			Index:   item.Index,
			RuleID:  item.RuleID,
			Message: item.Message,
		})
	}
	for _, e := range br.RollbackErrs {
		resp.RollbackErrs = append(resp.RollbackErrs, e.Error())
	}
	return resp
}

func (h *RuleHandler) CreateRule(c *gin.Context) {
	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40001, "invalid request body: "+err.Error())
		return
	}

	rule, err := h.svc.CreateRule(&req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidInput) {
			errorResponse(c, http.StatusBadRequest, 40002, err.Error())
			return
		}
		if errors.Is(err, service.ErrFirewallApply) {
			c.JSON(http.StatusFailedDependency, models.APIResponse{
				Code:    424001,
				Message: err.Error(),
				Data:    rule,
			})
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50001, "internal error: "+err.Error())
		return
	}

	createdResponse(c, rule)
}

func (h *RuleHandler) GetRule(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40003, "rule id is required")
		return
	}

	rule, err := h.svc.GetRule(id)
	if err != nil {
		if errors.Is(err, service.ErrRuleNotFound) {
			errorResponse(c, http.StatusNotFound, 40401, err.Error())
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50002, "internal error: "+err.Error())
		return
	}

	successResponse(c, rule)
}

func (h *RuleHandler) ListRules(c *gin.Context) {
	groupID := c.Query("group_id")
	action := c.Query("action")
	status := c.Query("status")

	page := parseIntParam(c.Query("page"), 1)
	pageSize := parseIntParam(c.Query("page_size"), 20)

	result, err := h.svc.ListRules(groupID, action, status, page, pageSize)
	if err != nil {
		errorResponse(c, http.StatusInternalServerError, 50003, "internal error: "+err.Error())
		return
	}

	successResponse(c, result)
}

func (h *RuleHandler) UpdateRule(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40004, "rule id is required")
		return
	}

	var req models.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40005, "invalid request body: "+err.Error())
		return
	}

	rule, rbInfo, err := h.svc.UpdateRule(id, &req)
	if err != nil {
		respData := gin.H{
			"rule":         rule,
			"rollback_info": toRollbackInfoResponse(rbInfo),
		}

		if errors.Is(err, service.ErrRuleNotFound) {
			errorResponse(c, http.StatusNotFound, 40402, err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidInput) {
			errorResponse(c, http.StatusBadRequest, 40006, err.Error())
			return
		}
		if errors.Is(err, service.ErrRollbackOccurred) {
			c.JSON(http.StatusConflict, models.APIResponse{
				Code:    409001,
				Message: "Operation failed and rolled back to previous state: " + err.Error(),
				Data:    respData,
			})
			return
		}
		if errors.Is(err, service.ErrFirewallApply) {
			c.JSON(http.StatusFailedDependency, models.APIResponse{
				Code:    424002,
				Message: err.Error(),
				Data:    respData,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    50004,
			Message: "internal error: " + err.Error(),
			Data:    respData,
		})
		return
	}

	successResponse(c, gin.H{
		"rule":         rule,
		"rollback_info": toRollbackInfoResponse(rbInfo),
	})
}

func (h *RuleHandler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40007, "rule id is required")
		return
	}

	rbInfo, err := h.svc.DeleteRule(id)
	if err != nil {
		respData := gin.H{
			"id":            id,
			"rollback_info": toRollbackInfoResponse(rbInfo),
		}

		if errors.Is(err, service.ErrRuleNotFound) {
			errorResponse(c, http.StatusNotFound, 40403, err.Error())
			return
		}
		if errors.Is(err, service.ErrRollbackOccurred) {
			c.JSON(http.StatusConflict, models.APIResponse{
				Code:    409002,
				Message: "Delete failed and rolled back: " + err.Error(),
				Data:    respData,
			})
			return
		}
		if errors.Is(err, service.ErrFirewallApply) {
			c.JSON(http.StatusFailedDependency, models.APIResponse{
				Code:    424003,
				Message: err.Error(),
				Data:    respData,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Code:    50005,
			Message: "internal error: " + err.Error(),
			Data:    respData,
		})
		return
	}

	successResponse(c, gin.H{
		"id":            id,
		"rollback_info": toRollbackInfoResponse(rbInfo),
	})
}

func (h *RuleHandler) SyncRules(c *gin.Context) {
	rbInfo, err := h.svc.SyncAllRules()
	if err != nil {
		respData := gin.H{
			"backend":      h.svc.BackendName(),
			"rollback_info": toRollbackInfoResponse(rbInfo),
		}

		if rbInfo != nil && rbInfo.Rollbacked {
			c.JSON(http.StatusConflict, models.APIResponse{
				Code:    409003,
				Message: "Sync failed and rolled back: " + err.Error(),
				Data:    respData,
			})
			return
		}

		c.JSON(http.StatusFailedDependency, models.APIResponse{
			Code:    424004,
			Message: "sync failed: " + err.Error(),
			Data:    respData,
		})
		return
	}

	successResponse(c, gin.H{
		"synced":       true,
		"backend":      h.svc.BackendName(),
		"rollback_info": toRollbackInfoResponse(rbInfo),
	})
}

func (h *RuleHandler) BatchCreateRules(c *gin.Context) {
	var req models.BatchCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40010, "invalid request body: "+err.Error())
		return
	}

	result := h.svc.BatchCreateRules(req.Rules)
	resp := toBatchResultResponse(result)

	if result.Rollbacked {
		c.JSON(http.StatusConflict, models.APIResponse{
			Code:    409004,
			Message: "Batch create failed, all changes rolled back",
			Data:    resp,
		})
		return
	}

	if result.Failed > 0 {
		c.JSON(http.StatusMultiStatus, models.APIResponse{
			Code:    207001,
			Message: "Some items failed",
			Data:    resp,
		})
		return
	}

	successResponse(c, resp)
}

func (h *RuleHandler) BatchUpdateRules(c *gin.Context) {
	var req models.BatchUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, http.StatusBadRequest, 40011, "invalid request body: "+err.Error())
		return
	}

	result := h.svc.BatchUpdateRules(req.Rules)
	resp := toBatchResultResponse(result)

	if result.Rollbacked {
		c.JSON(http.StatusConflict, models.APIResponse{
			Code:    409005,
			Message: "Batch update failed, all changes rolled back",
			Data:    resp,
		})
		return
	}

	if result.Failed > 0 {
		c.JSON(http.StatusMultiStatus, models.APIResponse{
			Code:    207002,
			Message: "Some items failed",
			Data:    resp,
		})
		return
	}

	successResponse(c, resp)
}

func (h *RuleHandler) GetHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"backend": h.svc.BackendName(),
	})
}

func parseIntParam(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return v
}
