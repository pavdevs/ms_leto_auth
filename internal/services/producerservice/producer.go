package producerservice

import (
	"context"

	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

type KafkaProducer struct {
	Writer *kafka.Writer
	Config Config
	logger *logrus.Logger
}

func NewKafkaProducer(config Config, logger *logrus.Logger) (*KafkaProducer, error) {
	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{config.brokers},
		Topic:   config.topic,
	})

	return &KafkaProducer{
		Writer: writer,
		Config: config,
		logger: logger,
	}, nil
}

func (kp *KafkaProducer) SendMessage(key, value string) error {
	message := kafka.Message{
		Key:   []byte(key),
		Value: []byte(value),
	}

	err := kp.Writer.WriteMessages(context.Background(), message)

	if err != nil {
		kp.logger.Error(err)
		return err
	}

	kp.logger.Info("Delivered message to topic ", kp.Config.topic)

	return nil
}

func (kp *KafkaProducer) Close() {
	kp.Writer.Close()
}
