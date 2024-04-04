package repositorycontainer

import (
	database "com.pavdevs.learningservice/internal/database"
	"com.pavdevs.learningservice/internal/repositories/userrepository"
	"github.com/sirupsen/logrus"
)

type RepositoryContainer struct {
	UserRepository *userrepository.UserRepository
}

func NewRepositoryContainer(db *database.Database, logger *logrus.Logger) *RepositoryContainer {

	userRepository := userrepository.NewUserRepository(db, logger)

	return &RepositoryContainer{
		UserRepository: userRepository,
	}
}
