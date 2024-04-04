package server

import (
	"context"
	"net/http"
	"os"

	_ "com.pavdevs.learningservice/docs"
	"com.pavdevs.learningservice/internal/api/userapi"
	"com.pavdevs.learningservice/internal/repositories/repositorycontainer"
	consumer "com.pavdevs.learningservice/internal/services/consumerservice"
	producer "com.pavdevs.learningservice/internal/services/producerservice"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	httpSwagger "github.com/swaggo/http-swagger"
)

type Server struct {
	config              Config
	logger              *logrus.Logger
	repositoryContainer *repositorycontainer.RepositoryContainer
}

func NewServer(config Config, logger *logrus.Logger, repositoryContainer *repositorycontainer.RepositoryContainer) *Server {
	return &Server{
		config:              config,
		logger:              logger,
		repositoryContainer: repositoryContainer,
	}
}

func (s *Server) Start() error {

	s.logger.Info("Prepare router")

	p, prErr := prepareProducer(s)

	if prErr != nil {
		s.logger.Info(prErr)
	}

	c, conErr := prepareConsumer(s)

	if conErr != nil {
		s.logger.Info(conErr)
	}

	ctx := context.Background()

	go consumeMessages(ctx, c)

	router := mux.NewRouter()
	userApi := userapi.NewUserHandler(s.repositoryContainer, s.logger, p)

	userApi.Register(router)

	s.logger.Info("Router register endpoints")

	router.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	s.logger.Info("Router register swagger")

	s.logger.Info("Server started at " + s.config.Host + ":" + s.config.Port)

	if err := http.ListenAndServe(s.config.Host+":"+s.config.Port, router); err != nil {
		s.logger.Info(err)
	}

	return nil
}

func prepareProducer(s *Server) (*producer.KafkaProducer, error) {
	return producer.NewKafkaProducer(
		producer.NewConfig(
			os.Getenv("KAFKA_BROKER"),
			"auth_service_events"),
		s.logger)
}

func prepareConsumer(s *Server) (*consumer.KafkaConsumer, error) {
	return consumer.NewKafkaConsumer(
		consumer.NewConfig(
			os.Getenv("KAFKA_BROKER"),
			"auth_service_events",
			"auth"),
		s.logger)
}

func consumeMessages(ctx context.Context, consumer *consumer.KafkaConsumer) {
	for {
		consumer.ReadMessage(ctx)
	}
}
