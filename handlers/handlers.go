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

	rule, err := h.svc.UpdateRule(id, &req)
	if err != nil {
		if errors.Is(err, service.ErrRuleNotFound) {
			errorResponse(c, http.StatusNotFound, 40402, err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidInput) {
			errorResponse(c, http.StatusBadRequest, 40006, err.Error())
			return
		}
		if errors.Is(err, service.ErrFirewallApply) {
			c.JSON(http.StatusFailedDependency, models.APIResponse{
				Code:    424002,
				Message: err.Error(),
				Data:    rule,
			})
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50004, "internal error: "+err.Error())
		return
	}

	successResponse(c, rule)
}

func (h *RuleHandler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		errorResponse(c, http.StatusBadRequest, 40007, "rule id is required")
		return
	}

	err := h.svc.DeleteRule(id)
	if err != nil {
		if errors.Is(err, service.ErrRuleNotFound) {
			errorResponse(c, http.StatusNotFound, 40403, err.Error())
			return
		}
		if errors.Is(err, service.ErrFirewallApply) {
			errorResponse(c, http.StatusFailedDependency, 424003, err.Error())
			return
		}
		errorResponse(c, http.StatusInternalServerError, 50005, "internal error: "+err.Error())
		return
	}

	successResponse(c, gin.H{"id": id})
}

func (h *RuleHandler) SyncRules(c *gin.Context) {
	err := h.svc.SyncAllRules()
	if err != nil {
		errorResponse(c, http.StatusFailedDependency, 424004, "sync failed: "+err.Error())
		return
	}

	successResponse(c, gin.H{"synced": true, "backend": h.svc.BackendName()})
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
