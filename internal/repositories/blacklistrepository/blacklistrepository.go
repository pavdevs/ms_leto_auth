package blacklistrepository

import (
	"com.pavdevs.learningservice/internal/database"
	"fmt"
	"github.com/sirupsen/logrus"
)

type BlacklistRepository struct {
	database *database.Database
	logger   *logrus.Logger
}

func NewBlacklistRepository(database *database.Database, logger *logrus.Logger) *BlacklistRepository {
	return &BlacklistRepository{
		database: database,
		logger:   logger,
	}
}

func (b *BlacklistRepository) AddToBlacklist(userId int) error {
	var err error

	if err = pingDatabase(b.database); err != nil {
		return err
	}

	query := "INSERT INTO blacklist (user_id) VALUES ($1)"

	_, err = b.database.DB.Exec(query, userId)

	if err != nil {
		return err
	}

	return nil
}

func (b *BlacklistRepository) RemoveFromBlacklist(userId int) error {
	var err error

	if err = pingDatabase(b.database); err != nil {
		return err
	}

	query := "DELETE FROM blacklist WHERE user_id = ($1)"

	_, err = b.database.DB.Exec(query, userId)

	if err != nil {
		return err
	}

	return nil
}

func (b *BlacklistRepository) IsUserInBlacklist(userId int) (bool, error) {
	var err error

	if err = pingDatabase(b.database); err != nil {
		return false, err
	}

	var isExists bool

	query := "SELECT EXISTS (SELECT 1 FROM blacklist WHERE user_id = $1)"

	err = b.database.DB.QueryRow(query, userId).Scan(&isExists)

	if err != nil {
		return false, err
	}

	return isExists, nil
}

func pingDatabase(db *database.Database) error {
	if err := db.DB.Ping(); err != nil {
		return fmt.Errorf("error pinging the database: %v", err)
	}

	return nil
}
