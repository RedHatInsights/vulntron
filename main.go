package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_grype"

	kafka "github.com/Shopify/sarama"
	_ "github.com/lib/pq"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	cfgFile     string
	logFileName string
)

func init() {
	// Command-line flags
	flag.StringVar(&cfgFile, "config", "config.yaml", "Config file location")

	timeStamp := time.Now().Format("2006-01-02_15-04-05")
	logFileName = fmt.Sprintf("Grype_eng_%s.log", timeStamp)

}

func main() {
	flag.Parse()

	// Read configuration from file
	config, err := config.ReadConfig(cfgFile)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		os.Exit(1)
	}
	config.Vulntron.Logging.LogFileName = logFileName

	log_config := config.Vulntron

	// OS variables initialization
	ddUrl := os.Getenv("DEFECT_DOJO_URL")
	ddUsername := os.Getenv("DEFECT_DOJO_USERNAME")
	ddPassword := os.Getenv("DEFECT_DOJO_PASSWORD")
	ocToken := os.Getenv("OC_TOKEN")

	namespacesString := os.Getenv("OC_NAMESPACE_LIST")
	namespacesRegex := os.Getenv("OC_NAMESPACE_REGEX")

	ctx := context.Background()

	// Create API client for Defect Dojo
	client, err := vulntron_dd.TokenInit(ddUsername, ddPassword, ddUrl, &ctx, log_config)
	if err != nil {
		fmt.Printf("Error initializing DefectDojo client: %v\n", err)
		os.Exit(2)
	}

	// Check RunType from config
	switch config.Vulntron.RunType {

	case "auto":
		utils.DebugPrint(log_config, "Selected message type: Auto")

		var allPodInfos []PodInfo

		// Create a rest.Config object
		ocConfig := &rest.Config{
			Host:        config.Loader.ServerURL,
			BearerToken: ocToken,
		}

		// Create a Kubernetes clientset using the rest.Config
		clientset, err := kubernetes.NewForConfig(ocConfig)
		if err != nil {
			fmt.Printf("Error creating Kubernetes client: %v\n", err)
			os.Exit(1)
		}

		ocNamespaces := make([]string, 0)
		if namespacesRegex != "" {
			// Compile the regular expression
			regex, err := regexp.Compile(namespacesRegex)
			if err != nil {
				fmt.Printf("Error compiling regex: %v\n", err)
				return
			}

			namespaceList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				panic(err.Error())
			}

			// Store namespaces that match the regex pattern
			for _, namespace := range namespaceList.Items {
				if regex.MatchString(namespace.Name) {
					ocNamespaces = append(ocNamespaces, namespace.Name)
				}
			}
		} else {
			namespaceStrings := strings.Split(namespacesString, ",")
			ocNamespaces = append(ocNamespaces, namespaceStrings...)
		}

		// Iterate over each namespace
		for _, namespace := range ocNamespaces {
			utils.DebugPrint(log_config, namespace)
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
				if namespace == "ephemeral-wycitx" { //pod.Name != "ahoj" { // "env-ephemeral-jngktw-mbop-6cbd9c97c6-5zgjf" {
					var containerInfos []ContainerInfo

					for _, container := range pod.Spec.Containers {

						var containerID string
						for _, containerStatus := range pod.Status.ContainerStatuses {
							if containerStatus.Image == container.Image {
								containerID = containerStatus.ImageID
							}
						}

						if containerID == "" {
							// imageID mismatch (possible :latest) match on name (containerId preferred)
							for _, containerStatus := range pod.Status.ContainerStatuses {
								if containerStatus.Name == container.Name {
									containerID = containerStatus.ImageID
								}
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

		/*
			// TODO: update this check
			// Check if all namespaces are the same as the one specified in config
			expectedNamespace := ocNamespaces[0]
			for _, podInfo := range podInfos {
				if podInfo.Namespace != expectedNamespace {
					fmt.Printf("Error: Namespace mismatch in pod %s. Expected: %s, Actual: %s\n", podInfo.Pod_Name, expectedNamespace, podInfo.Namespace)
					os.Exit(1)
				}
			}
		*/

		// Check system settings
		systemSettings, err := vulntron_dd.ListSystemSettings(&ctx, client, log_config)
		if err != nil {
			fmt.Printf("Error getting system settings: %v\n", err)
			os.Exit(1)
		}
		for _, pt := range *systemSettings.Results {
			if pt.MaxDupes == nil ||
				*pt.EnableDeduplication != config.DefectDojo.EnableDeduplication ||
				*pt.DeleteDuplicates != config.DefectDojo.DeleteDuplicates ||
				*pt.MaxDupes != config.DefectDojo.MaxDuplicates {
				// Set updated system settings
				utils.DebugPrint(log_config, "Defect Dojo System settings are not correct!")
				err = vulntron_dd.UpdateSystemSettings(
					&ctx,
					client,
					*pt.Id,
					config.DefectDojo.EnableDeduplication,
					config.DefectDojo.DeleteDuplicates,
					config.DefectDojo.MaxDuplicates,
					log_config)
				if err != nil {
					fmt.Printf("Error setting system settings: %v\n", err)
					os.Exit(1)
				}
			} else {
				utils.DebugPrint(log_config, "Defect Dojo System settings match config.")
			}
		}

		// List all Products(namespaces) in current DD deployment
		productTypes, err := vulntron_dd.ListProductTypes(&ctx, client, log_config)
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
		for _, namespace := range ocNamespaces {
			var productTypeId int
			if _, found := existingProductTypeNames[namespace]; !found {
				// Create new Product Type (namespace name) if it doesn't exist already
				productTypeId, err = vulntron_dd.CreateProductType(&ctx, client, namespace, log_config)
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

		for counter, pod := range allPodInfos {
			utils.DebugPrint(log_config, "Checking %d out of %d pods", counter+1, len(allPodInfos))
			ProductTypeId := namespaceProductTypeIds[pod.Namespace]

			// create new Product (container name) if it doesn't exist already
			productCreated, productId, err := vulntron_dd.CreateProduct(&ctx, client, pod.Pod_Name, ProductTypeId, log_config)
			if err != nil {
				fmt.Printf("Error getting product types: %v\n", err)
				os.Exit(1)
			}

			if productCreated {
				ProductIdInt = productId
			} else {
				// List all Products (namespaces) in current DD deployment to get Product Id
				ProductIdInt, err = vulntron_dd.ListProducts(&ctx, client, pod.Pod_Name, log_config)
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

			// Get list of all engagements for the given ProductID
			engs, err := vulntron_dd.ListEngagements(&ctx, client, ProductIdInt, "", log_config)
			if err != nil {
				fmt.Printf("Error Listing engagments in product: %v\n", err)
				os.Exit(1)
			}

			// Check Engagements tag(s) against the tag(s) from the currently scanned pod
			var engagementFound bool = false
			var engagementId int = 0
			for _, pt := range *engs.Results {
				var engagement_tags []string
				engagement_tags = append(engagement_tags, *pt.Tags...)
				if utils.CompareLists(engagement_tags, original_tags) {
					engagementFound = true
					break
				} else {
					engagementId = *pt.Id
				}
			}

			if engagementFound {
				// Current tags are the same as stored tags in already completed engagement
				utils.DebugPrint(log_config, "Engagement with the same image tag already exists, skipping new engagements for pod: %s", pod.Pod_Name)

			} else if engagementId == 0 && !productCreated {
				// No access to image
				utils.DebugPrint(log_config, "There are no tags - Possible no access to image!")

			} else {

				if productCreated {
					utils.DebugPrint(log_config, "No tags yet")

				} else {
					//TODO No access creates new engagement - check message?
					utils.DebugPrint(log_config, "Tags are not the same")
					utils.DebugPrint(log_config, "Old engagement has tag %d", engagementId)
				}

				// remove old Engagement for the given Product
				if engagementId != 0 {
					err = vulntron_dd.DeleteEngagement(&ctx, client, engagementId, log_config)
					if err != nil {
						fmt.Printf("Error Deleting old engagement %v\n", err)
						os.Exit(1)
					}
				}

				err = vulntron_dd.CreateEngagement(&ctx, client, original_tags, ProductIdInt, log_config)
				if err != nil {
					fmt.Printf("Error Creating new engagement %v\n", err)
					// TODO handle this gracefully
					// os.Exit(1)
				}

				for _, container := range pod.Containers {
					utils.DebugPrint(log_config, "Starting scanning process for: %s", container.Image)

					// Run Grype
					_, fileName, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, container.Image, log_config)
					if err != nil {
						fmt.Printf("Error running Grype for image %s: %v\n", container.Image, err)
						continue
					}

					err = vulntron_dd.ImportGrypeScan(&ctx, client, pod.Namespace, container.Container_Name, container.ImageID, pod.Pod_Name, fileName, log_config)
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
		consumerGroup := os.Getenv("KAFKA_CONSUMER_GROUP")

		utils.DebugPrint(log_config, "Brokers: %s", brokers)
		utils.DebugPrint(log_config, "Consumer group: %s", consumerGroup)

		group, err := kafka.NewConsumerGroup(brokers, consumerGroup, config)
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
