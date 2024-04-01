package consumerservice

import (
	"context"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

type KafkaConsumer struct {
	Reader *kafka.Reader
	Config Config
	logger *logrus.Logger
}

func NewKafkaConsumer(config Config, logger *logrus.Logger) (*KafkaConsumer, error) {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        []string{config.brokers},
		GroupID:        config.groupId,
		Topic:          config.topic,
		SessionTimeout: time.Second * 10,
	})

	return &KafkaConsumer{
		Reader: reader,
		Config: config,
		logger: logger,
	}, nil
}

func (kc *KafkaConsumer) ReadMessage(ctx context.Context) (string, error) {
	message, err := kc.Reader.ReadMessage(ctx)
	if err != nil {
		kc.logger.Error("failed to read message: ", err)
		return "", err
	}

	kc.logger.Info("Received message from topic ", kc.Config.topic, ": ", string(message.Value))

	return string(message.Value), nil
}

func (kc *KafkaConsumer) Close() {
	if err := kc.Reader.Close(); err != nil {
		kc.logger.Error("failed to close reader: ", err)
	}
}
