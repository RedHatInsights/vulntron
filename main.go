package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_grype"

	kafka "github.com/Shopify/sarama"
	_ "github.com/lib/pq"
	v1 "k8s.io/api/core/v1"
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

type PodInfo struct {
	Pod_Name   string          `json:"Pod_Name"`
	Namespace  string          `json:"Namespace"`
	Containers []ContainerInfo `json:"Containers"`
}
type ContainerInfo struct {
	Container_Name string `json:"Container_Name"`
	Image          string `json:"Image"`
	ImageID        string `json:"ImageID"`
	StartTime      string `json:"StartTime"`
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
	runType string
	cfgFile string
)

func init() {
	// Command-line flags
	flag.StringVar(&cfgFile, "config", "config.yaml", "Config file location")
	flag.StringVar(&runType, "type", "auto", "Message type: kafka or auto")
}

func main() {
	flag.Parse()

	// TODO: check DD settings config, set deduplicaion, etc.

	// Read configuration from file
	config, err := config.ReadConfig(cfgFile)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	dd_url := os.Getenv("DEFECT_DOJO_URL")
	dd_username := os.Getenv("DEFECT_DOJO_USERNAME")
	dd_password := os.Getenv("DEFECT_DOJO_PASSWORD")

	client, err := vulntron_dd.TokenInit(dd_username, dd_password, dd_url, &ctx)
	if err != nil {
		fmt.Printf("Error initializing DefectDojo client: %v\n", err)
		os.Exit(2)
	}

	// Check the value of the -type flag
	switch runType {

	// TODO move to config
	case "auto":
		utils.DebugPrint("Selected message type: Auto")

		var json_file_input bool = false
		var pods []v1.Pod
		var allPodInfos []PodInfo

		if json_file_input {
			// Read the JSON file
			jsonFile, err := os.ReadFile("/app/ee_comp.json")
			if err != nil {
				fmt.Printf("Error reading JSON file: %v\n", err)
				os.Exit(1)
			}

			// Unmarshal JSON into PodList
			var podList v1.PodList
			if err := json.Unmarshal(jsonFile, &podList); err != nil {
				fmt.Printf("Error unmarshalling JSON: %v\n", err)
				os.Exit(1)
			}

			pods = podList.Items

			// Iterate through each pod and populate the PodInfo structure
			for _, pod := range pods {
				if pod.Name != "ahoj" { // "env-ephemeral-jngktw-mbop-6cbd9c97c6-5zgjf" {
					var containerInfos []ContainerInfo

					for _, container := range pod.Spec.Containers {

						var containerID string
						for _, containerStatus := range pod.Status.ContainerStatuses {
							if containerStatus.Image == container.Image {
								containerID = containerStatus.ImageID
							}

						}
						parts := strings.SplitN(containerID, "@", -1)
						containerID = parts[len(parts)-1]

						containerInfo := ContainerInfo{
							Container_Name: container.Name,
							Image:          container.Image,
							ImageID:        containerID,
							StartTime:      pod.Status.StartTime.Time.Format("2006-01-02T15:04:05Z"),
						}
						containerInfos = append(containerInfos, containerInfo)
					}

					podInfo := PodInfo{
						Pod_Name:   pod.Name,
						Namespace:  pod.Namespace,
						Containers: containerInfos,
					}
					allPodInfos = append(allPodInfos, podInfo)
				}
			}

		} else {

			// Create a rest.Config object
			oc_token := os.Getenv("OC_TOKEN")
			oc_config := &rest.Config{
				Host:        config.Loader.ServerURL,
				BearerToken: oc_token,
			}

			// Create a Kubernetes clientset using the rest.Config
			clientset, err := kubernetes.NewForConfig(oc_config)
			if err != nil {
				fmt.Printf("Error creating Kubernetes client: %v\n", err)
				os.Exit(1)
			}

			// Iterate over each namespace
			for _, namespace := range config.Loader.Namespaces {
				utils.DebugPrint(namespace)
				// Example: List Pods in the specified namespace
				podList, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					fmt.Printf("Error listing pods in namespace %s: %v\n", namespace, err)
					continue // Continue to the next namespace in case of error
				}
				pods := podList.Items

				var podInfos []PodInfo

				// Iterate through each pod and populate the PodInfo structure
				for _, pod := range pods {
					if pod.Name != "ahoj" { // "env-ephemeral-jngktw-mbop-6cbd9c97c6-5zgjf" {
						var containerInfos []ContainerInfo

						for _, container := range pod.Spec.Containers {

							var containerID string
							for _, containerStatus := range pod.Status.ContainerStatuses {
								if containerStatus.Image == container.Image {
									containerID = containerStatus.ImageID
								}

							}
							parts := strings.SplitN(containerID, "@", -1)
							containerID = parts[len(parts)-1]

							containerInfo := ContainerInfo{
								Container_Name: container.Name,
								Image:          container.Image,
								ImageID:        containerID,
								StartTime:      pod.Status.StartTime.Time.Format("2006-01-02T15:04:05Z"),
							}
							containerInfos = append(containerInfos, containerInfo)
						}

						podInfo := PodInfo{
							Pod_Name:   pod.Name,
							Namespace:  pod.Namespace,
							Containers: containerInfos,
						}
						podInfos = append(podInfos, podInfo)
					}
				}

				// Append PodInfos for current namespace to allPodInfos
				allPodInfos = append(allPodInfos, podInfos...)
			}

		}

		/*
			// TODO: update this check
			// Check if all namespaces are the same as the one specified in config
			expectedNamespace := config.Loader.Namespaces[0]
			for _, podInfo := range podInfos {
				if podInfo.Namespace != expectedNamespace {
					fmt.Printf("Error: Namespace mismatch in pod %s. Expected: %s, Actual: %s\n", podInfo.Pod_Name, expectedNamespace, podInfo.Namespace)
					os.Exit(1)
				}
			}
		*/

		// List all Products(namespaces) in current DD deployment
		productTypes, err := vulntron_dd.ListProductTypes(&ctx, client)
		if err != nil {
			fmt.Printf("Error getting product types: %v\n", err)
			os.Exit(1)
		}

		namespaceProductTypeIds := make(map[string]int)

		existingProductTypeNames := make(map[string]bool)
		for _, pt := range *productTypes.Results {
			existingProductTypeNames[pt.Name] = true
		}

		// Iterate over namespaces and create product types if they don't exist
		for _, namespace := range config.Loader.Namespaces {
			var productTypeId int
			if _, found := existingProductTypeNames[namespace]; !found {
				// Create new Product Type (namespace name) if it doesn't exist already
				productTypeId, err = vulntron_dd.CreateProductType(&ctx, client, namespace)
				if err != nil {
					fmt.Printf("Error creating product type for namespace %s: %v\n", namespace, err)
					os.Exit(1)
				}
				// Optionally, update existingProductTypeNames map with the new product type name
				existingProductTypeNames[namespace] = true
			} else {
				// If product type exists, retrieve its ID
				for _, pt := range *productTypes.Results {
					if pt.Name == namespace {
						productTypeId = *pt.Id
						break
					}
				}
			}
			namespaceProductTypeIds[namespace] = productTypeId
		}

		var ProductIdInt int

		// create new tag for current scan and engagement
		for _, pod := range allPodInfos {
			ProductTypeId := namespaceProductTypeIds[pod.Namespace]

			// create new Product (container name) if it doesn't exist already
			productCreated, productId, err := vulntron_dd.CreateProduct(&ctx, client, pod.Pod_Name, ProductTypeId)
			if err != nil {
				fmt.Printf("Error getting product types: %v\n", err)
				os.Exit(1)
			}

			if productCreated {
				ProductIdInt = productId
			} else {
				// List all Products (namespaces) in current DD deployment to get Product Id
				ProductIdInt, err = vulntron_dd.ListProducts(&ctx, client, pod.Pod_Name)
				if err != nil {
					fmt.Printf("Error Listing product types: %v\n", err)
					os.Exit(1)
				}

			}

			// Get list of Image hashes from source
			var original_tags []string
			uniqueTags := make(map[string]bool)

			for _, container := range pod.Containers {
				if !uniqueTags[container.ImageID] {
					original_tags = append(original_tags, container.ImageID)
					uniqueTags[container.ImageID] = true
				}
			}

			engs, err := vulntron_dd.ListEngagements(&ctx, client, ProductIdInt)
			if err != nil {
				fmt.Printf("Error Listing engagments in product: %v\n", err)
				os.Exit(1)
			}

			var engagement_found bool = false
			var engagementId int = 0
			for _, pt := range *engs.Results {
				var engagement_tags []string
				engagement_tags = append(engagement_tags, *pt.Tags...)
				if utils.CompareLists(engagement_tags, original_tags) {
					engagement_found = true
					break
				} else {
					engagementId = *pt.Id
				}
			}

			if engagement_found {
				utils.DebugPrint("Tags are the same, skipping new engagements for pod: %s", pod.Pod_Name)
				//break

			} else if engagementId == 0 && !productCreated {
				utils.DebugPrint("There are no tags - Possible no access to image!")

			} else {

				if productCreated {
					utils.DebugPrint("No tags yet")
				} else {
					//TODO No access creates new engagement - check message?
					utils.DebugPrint("Tags are not the same")
					utils.DebugPrint("Old engagement has tag %d", engagementId)
				}

				if engagementId != 0 {
					err = vulntron_dd.DeleteEngagement(&ctx, client, engagementId)
					if err != nil {
						fmt.Printf("Error Deleting old engagement %v\n", err)
						os.Exit(1)
					}
				}

				err = vulntron_dd.CreateEngagement(&ctx, client, original_tags, ProductIdInt)
				if err != nil {
					fmt.Printf("Error Creating new engagement %v\n", err)
					os.Exit(1)
				}

				for _, container := range pod.Containers {
					utils.DebugPrint("Starting scanning process for: %s", container.Image)

					// Run Grype
					_, fileName, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, container.Image)
					if err != nil {
						fmt.Printf("Error running Grype for image %s: %v\n", container.Image, err)
						continue
					}

					err = vulntron_dd.ImportGrypeScan(&ctx, client, pod.Namespace, container.Container_Name, container.ImageID, pod.Pod_Name, fileName)
					if err != nil {
						fmt.Printf("Error importing Grype scan %s: %v\n", container.Container_Name, err)
						continue
					}
				}
			}
		}

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

	default:
		fmt.Println("Invalid message type. Please use either 'kafka' or 'auto'.")
		os.Exit(1)
	}

	// add clean up for created files

}
