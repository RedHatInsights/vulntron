package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_grype"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_syft"

	kafka "github.com/Shopify/sarama"
	_ "github.com/lib/pq"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "user"
	password = "password"
	dbname   = "vulntrondb"
)

type ContainerInfo struct {
	Container string `json:"Container"`
	Image     string `json:"Image"`
	StartTime string `json:"StartTime"`
}
type PodInfo struct {
	Pod        string          `json:"Pod"`
	Namespace  string          `json:"Namespace"`
	Containers []ContainerInfo `json:"Containers"`
}

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

var (
	runType   string
	cfgFile   string
	timestamp string
	imageName string
	component string
	db        *sql.DB
)

func init() {
	// Command-line flags
	flag.StringVar(&cfgFile, "config", "config.yaml", "Config file")
	flag.StringVar(&runType, "type", "auto", "Message type: kafka or auto or single")
	flag.StringVar(&timestamp, "timestamp", "", "Timestamp")
	flag.StringVar(&imageName, "imagename", "", "Image name")
	flag.StringVar(&component, "component", "", "Component name")
}

func main() {
	flag.Parse()

	// Read configuration from file
	config, err := config.ReadConfig(cfgFile)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		os.Exit(1)
	}

	// Connect to the PostgreSQL database
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	fmt.Println("PSQL config: ", psqlInfo)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		fmt.Println("Error connecting to the database:", err)
		return
	}
	defer db.Close()

	// Check the value of the -type flag
	switch runType {
	case "kafka":
		fmt.Println("Selected message type: Kafka")
		config := kafka.NewConfig()
		config.Consumer.Return.Errors = true
		config.Consumer.Offsets.Initial = kafka.OffsetOldest
		brokers := []string{os.Getenv("KAFKA_BROKER")}
		topic := []string{os.Getenv("KAFKA_TOPIC")}
		consumergroup := "console-consumer-28827"

		utils.DebugPrint("Brokers: %s", brokers)
		utils.DebugPrint("Consumer group: %s", consumergroup)

		group, err := kafka.NewConsumerGroup(brokers, consumergroup, config)
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
		ctx := context.Background()
		for {
			handler := ConsumerGroupHandler{}

			// `Consume` should be called inside an infinite loop, when a
			// server-side rebalance happens, the consumer session will need to be
			// recreated to get the new claims
			err := group.Consume(ctx, topic, handler)
			if err != nil {
				panic(err)
			}
		}

	case "auto":
		utils.DebugPrint("Selected message type: Auto")

		// Create a rest.Config object
		oc_config := &rest.Config{
			Host:        config.Loader.ServerURL,
			BearerToken: config.Loader.Token,
		}

		// Create a Kubernetes clientset using the rest.Config
		clientset, err := kubernetes.NewForConfig(oc_config)
		if err != nil {
			fmt.Printf("Error creating Kubernetes client: %v\n", err)
			os.Exit(1)
		}

		// Example: List Pods in the specified namespace
		pods, err := clientset.CoreV1().Pods(config.Loader.Namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("Error listing pods: %v\n", err)
			os.Exit(1)
		}

		// Create a slice to hold the PodInfo objects
		var podInfos []PodInfo

		// Iterate through each pod and populate the PodInfo structure
		for _, pod := range pods.Items {
			var containerInfos []ContainerInfo
			for _, container := range pod.Spec.Containers {
				containerInfo := ContainerInfo{
					Container: container.Name,
					Image:     container.Image,
					StartTime: pod.Status.StartTime.Time.Format("2006-01-02T15:04:05Z"),
				}
				containerInfos = append(containerInfos, containerInfo)
			}

			podInfo := PodInfo{
				Pod:        pod.Name,
				Namespace:  pod.Namespace,
				Containers: containerInfos,
			}
			podInfos = append(podInfos, podInfo)
		}

		// Convert podInfos to JSON
		podsJSON, err := json.MarshalIndent(podInfos, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling podInfos to JSON: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(podsJSON))

		// Loop through each pod and run Syft and Grype for each container's image
		for _, pod := range podInfos {
			for _, container := range pod.Containers {

				// Run Syft
				syftOutput, err := vulntron_syft.RunSyft(config.Vulntron, container.Image)
				if err != nil {
					fmt.Printf("Error running Syft for image %s: %v\n", container.Image, err)
					continue
				}

				// Run Grype
				grypeOutput, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, container.Image)
				if err != nil {
					fmt.Printf("Error running Grype for image %s: %v\n", container.Image, err)
					continue
				}

				// Insert the results into the database
				if container.StartTime == "" || container.Image == "" || container.Container == "" || grypeOutput == "" || syftOutput == "" {
					fmt.Println("Error: Database insert has missing fields.")
				} else {
					_, err = db.Exec("INSERT INTO deployments (image_name, deployment_date, scan_date, component_name, syft_output, grype_output) VALUES ($1, $2, $3, $4, $5, $6)",
						container.Image, container.StartTime, time.Now().UTC().Format("2006-01-02T15:04:05Z"), container.Container, syftOutput, grypeOutput)
					if err != nil {
						fmt.Printf("Error inserting into the database for image %s: %v\n", container.Image, err)
					}
				}
			}
		}

	case "single":
		utils.DebugPrint("Selected message type: Single")

		imageTag := imageName

		// Run syft
		syftOutput, err := vulntron_syft.RunSyft(config.Vulntron, imageTag)
		if err != nil {
			fmt.Println("Error running Syft:", err)
			os.Exit(1)
		}

		// Run grype
		grypeOutput, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, imageTag)
		if err != nil {
			fmt.Println("Error running Grype:", err)
			os.Exit(1)
		}

		// Insert the results into the database
		if timestamp == "" || imageName == "" || component == "" {
			fmt.Println("Error: --timestamp, --imagename, and --component are required for database insert.")
		} else {
			_, err = db.Exec("INSERT INTO deployments (image_name, deployment_date, scan_date, component_name, syft_output, grype_output) VALUES ($1, $2, $3, $4, $5, $6)",
				imageName, timestamp, time.Now().UTC().Format("2006-01-02T15:04:05Z"), component, syftOutput, grypeOutput)
			if err != nil {
				fmt.Println("Error inserting into the database:", err)
				os.Exit(1)
			}
		}

	default:
		fmt.Println("Invalid message type. Please use either 'kafka' or 'auto'.")
		os.Exit(1)
	}

}
