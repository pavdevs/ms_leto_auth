package repositorycontainer

import (
	database "com.pavdevs.learningservice/internal/database"
	"com.pavdevs.learningservice/internal/repositories/blacklistrepository"
	"com.pavdevs.learningservice/internal/repositories/userrepository"
	"github.com/sirupsen/logrus"
)

type RepositoryContainer struct {
	UserRepository      *userrepository.UserRepository
	BlacklistRepository *blacklistrepository.BlacklistRepository
}

func NewRepositoryContainer(db *database.Database, logger *logrus.Logger) *RepositoryContainer {

	userRepository := userrepository.NewUserRepository(db, logger)
	blacklistRepository := blacklistrepository.NewBlacklistRepository(db, logger)

	return &RepositoryContainer{
		UserRepository:      userRepository,
		BlacklistRepository: blacklistRepository,
	}
}
