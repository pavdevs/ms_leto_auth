package main

import (
	"os"

	"com.pavdevs.learningservice/internal/api/server"
	database "com.pavdevs.learningservice/internal/database"
	"com.pavdevs.learningservice/internal/repositories/repositorycontainer"
	"github.com/sirupsen/logrus"
)

// @title Learning Service
// @version 1.0
// @description API Server for Learning Service

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

func main() {

	logger := logrus.New()

	db, err := prepareDataBase(logger)
	repContainer := prepareRepositoryContainer(db, logger)
	s := prepareServer(logger, repContainer)

	if err != nil {
		logger.Info(err)
	}

	defer db.Disconnect()

	logger.Info("Start configuration for server")

	if serverErr := s.Start(); serverErr != nil {
		logger.Info(serverErr)
	}

	logger.Info("Server started at localhost:8080")
}

func prepareDataBase(logger *logrus.Logger) (*database.Database, error) {
	db := database.NewDatabase(database.Config{
		Host:     os.Getenv("DATABASE_HOST"),
		User:     os.Getenv("DATABASE_USER"),
		Password: os.Getenv("DATABASE_PASSWORD"),
		DBName:   os.Getenv("DATABASE_NAME"),
		SSLMode:  os.Getenv("DATABASE_SSLMODE"),
	}, logger)

	if err := db.Connect(); err != nil {
		return nil, err
	}

	return db, nil
}

func prepareRepositoryContainer(database *database.Database, logger *logrus.Logger) *repositorycontainer.RepositoryContainer {
	return repositorycontainer.NewRepositoryContainer(database, logger)
}

func prepareServer(logger *logrus.Logger, repositoryContainer *repositorycontainer.RepositoryContainer) *server.Server {
	return server.NewServer(server.Config{
		Host: "",
		Port: "8080",
	}, logger, repositoryContainer)
}
