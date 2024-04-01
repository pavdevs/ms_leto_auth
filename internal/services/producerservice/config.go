package producerservice

type Config struct {
	brokers string
	topic   string
}

func NewConfig(brokers, topic string) Config {
	return Config{
		brokers: brokers,
		topic:   topic,
	}
}
