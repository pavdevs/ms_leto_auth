package consumerservice

type Config struct {
	brokers string
	topic   string
	groupId string
}

func NewConfig(brokers, topic, groupId string) Config {
	return Config{
		brokers: brokers,
		topic:   topic,
		groupId: groupId,
	}
}
