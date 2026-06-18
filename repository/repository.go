package repository

import (
	"fmt"
	"securitygroup/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type RuleRepository interface {
	Create(rule *models.SecurityRule) error
	GetByID(id string) (*models.SecurityRule, error)
	List(groupID string, action string, status string, page int, pageSize int) (*models.RuleListResponse, error)
	Update(rule *models.SecurityRule) error
	Delete(id string) error
	ListAllActive() ([]models.SecurityRule, error)
}

type SQLiteRepository struct {
	db *gorm.DB
}

func NewSQLiteRepository(dbPath string) (*SQLiteRepository, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.AutoMigrate(&models.SecurityRule{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &SQLiteRepository{db: db}, nil
}

func NewSQLiteRepositoryWithDB(db *gorm.DB) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

func (r *SQLiteRepository) Create(rule *models.SecurityRule) error {
	return r.db.Create(rule).Error
}

func (r *SQLiteRepository) GetByID(id string) (*models.SecurityRule, error) {
	var rule models.SecurityRule
	err := r.db.Where("id = ?", id).First(&rule).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &rule, nil
}

func (r *SQLiteRepository) List(groupID string, action string, status string, page int, pageSize int) (*models.RuleListResponse, error) {
	query := r.db.Model(&models.SecurityRule{})

	if groupID != "" {
		query = query.Where("group_id = ?", groupID)
	}
	if action != "" {
		query = query.Where("action = ?", action)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	var rules []models.SecurityRule
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	if err := query.Order("priority ASC, created_at DESC").Offset(offset).Limit(pageSize).Find(&rules).Error; err != nil {
		return nil, err
	}

	return &models.RuleListResponse{
		Total: total,
		List:  rules,
	}, nil
}

func (r *SQLiteRepository) Update(rule *models.SecurityRule) error {
	return r.db.Save(rule).Error
}

func (r *SQLiteRepository) Delete(id string) error {
	return r.db.Delete(&models.SecurityRule{}, "id = ?", id).Error
}

func (r *SQLiteRepository) ListAllActive() ([]models.SecurityRule, error) {
	var rules []models.SecurityRule
	err := r.db.Where("status = ?", models.StatusActive).Find(&rules).Error
	return rules, err
}

func (r *SQLiteRepository) GetDB() *gorm.DB {
	return r.db
}
