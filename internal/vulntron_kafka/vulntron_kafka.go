package vulntronkafka

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	kafka "github.com/Shopify/sarama"
	_ "github.com/lib/pq"
)

// ConsumerGroupHandler represents a Sarama consumer group consumer
type ConsumerGroupHandler struct{}

// Setup is run at the beginning of a new session, before ConsumeClaim
func (ConsumerGroupHandler) Setup(kafka.ConsumerGroupSession) error { return nil }

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited
func (ConsumerGroupHandler) Cleanup(kafka.ConsumerGroupSession) error { return nil }

// ConsumeClaim must start a consumer loop of ConsumerGroupClaim's Messages().
func (ConsumerGroupHandler) ConsumeClaim(session kafka.ConsumerGroupSession, claim kafka.ConsumerGroupClaim) error {
	var wg sync.WaitGroup

	for message := range claim.Messages() {
		wg.Add(1)
		go func(message *kafka.ConsumerMessage) {
			defer wg.Done()

			fmt.Printf("Message topic:%q partition:%d offset:%d\n", message.Topic, message.Partition, message.Offset)
			session.MarkMessage(message, "")

			// Call the runSyft function for each consumed message
			//runSyft(message)
			//runGrype(message)
		}(message)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	return nil
}

func ProcessKafkaMode() {
	ctx := context.Background()
	consumeKafkaMessages(&ctx)
}

func consumeKafkaMessages(ctx *context.Context) {
	fmt.Println("Selected message type: Kafka")
	kafka_config := kafka.NewConfig()
	kafka_config.Consumer.Return.Errors = true
	kafka_config.Consumer.Offsets.Initial = kafka.OffsetOldest
	brokers := []string{os.Getenv("KAFKA_BROKER")}
	topic := []string{os.Getenv("KAFKA_TOPIC")}
	consumerGroup := os.Getenv("KAFKA_CONSUMER_GROUP")

	log.Printf("Brokers: %s", brokers)
	log.Printf("Consumer group: %s", consumerGroup)

	group, err := kafka.NewConsumerGroup(brokers, consumerGroup, kafka_config)
	if err != nil {
		panic(err)
	}
	defer func() { _ = group.Close() }()

	// Track errors
	go func() {
		for err := range group.Errors() {
			fmt.Println("ERROR", err)
		}
	}()

	// Iterate over consumer sessions.
	for {
		handler := ConsumerGroupHandler{}

		// `Consume` should be called inside an infinite loop, when a
		// server-side re-balance happens, the consumer session will need to be
		// recreated to get the new claims
		err := group.Consume(*ctx, topic, handler)
		if err != nil {
			panic(err)
		}
	}
}
