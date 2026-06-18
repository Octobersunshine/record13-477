package repository

import (
	"fmt"
	"securitygroup/models"

	"gorm.io/gorm"
)

type ApprovalRepository interface {
	Create(req *models.ApprovalRequest) error
	GetByID(id string) (*models.ApprovalRequest, error)
	List(status string, operationType string, applicant string, page int, pageSize int) (*models.ApprovalListResponse, error)
	Update(req *models.ApprovalRequest) error
	Delete(id string) error
	ListPending() ([]models.ApprovalRequest, error)
}

type SQLiteApprovalRepository struct {
	db *gorm.DB
}

func NewSQLiteApprovalRepository(db *gorm.DB) *SQLiteApprovalRepository {
	return &SQLiteApprovalRepository{db: db}
}

func (r *SQLiteApprovalRepository) AutoMigrate() error {
	if err := r.db.AutoMigrate(&models.ApprovalRequest{}); err != nil {
		return fmt.Errorf("failed to migrate approval table: %w", err)
	}
	return nil
}

func (r *SQLiteApprovalRepository) Create(req *models.ApprovalRequest) error {
	return r.db.Create(req).Error
}

func (r *SQLiteApprovalRepository) GetByID(id string) (*models.ApprovalRequest, error) {
	var req models.ApprovalRequest
	err := r.db.Where("id = ?", id).First(&req).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &req, nil
}

func (r *SQLiteApprovalRepository) List(status string, operationType string, applicant string, page int, pageSize int) (*models.ApprovalListResponse, error) {
	query := r.db.Model(&models.ApprovalRequest{})

	if status != "" {
		query = query.Where("status = ?", status)
	}
	if operationType != "" {
		query = query.Where("operation_type = ?", operationType)
	}
	if applicant != "" {
		query = query.Where("applicant = ?", applicant)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	var list []models.ApprovalRequest
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&list).Error; err != nil {
		return nil, err
	}

	return &models.ApprovalListResponse{
		Total: total,
		List:  list,
	}, nil
}

func (r *SQLiteApprovalRepository) Update(req *models.ApprovalRequest) error {
	return r.db.Save(req).Error
}

func (r *SQLiteApprovalRepository) Delete(id string) error {
	return r.db.Delete(&models.ApprovalRequest{}, "id = ?", id).Error
}

func (r *SQLiteApprovalRepository) ListPending() ([]models.ApprovalRequest, error) {
	var list []models.ApprovalRequest
	err := r.db.Where("status = ?", models.ApprovalPending).Order("created_at ASC").Find(&list).Error
	return list, err
}
