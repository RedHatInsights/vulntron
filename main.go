package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_grype"

	dd "github.com/doximity/defect-dojo-client-go"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	kafka "github.com/Shopify/sarama"
	_ "github.com/lib/pq"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type PodInfo struct {
	Pod_Name   string          `json:"Pod_Name"`
	Namespace  string          `json:"Namespace"`
	StartTime  string          `json:"StartTime"`
	Containers []ContainerInfo `json:"Containers"`
}
type ContainerInfo struct {
	Container_Name string `json:"Container_Name"`
	Image          string `json:"Image"`
	ImageID        string `json:"ImageID"`
}

var (
	cfgFile string
)

func init() {
	// Command-line flags
	flag.StringVar(&cfgFile, "config", "config.yaml", "Config file location")
}

// Initialize logging based on configuration
func setupLogging(cfg config.VulntronConfig) {
	// Set log flags
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var logFile *os.File
	if cfg.Logging.LogFile {
		logPath := filepath.Join(cfg.Logging.LogFileLocation, cfg.Logging.LogFileName)

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
			log.Fatalf("Error creating directory for log file: %v", err)
		}

		// Open log file
		var err error
		logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}

		// Set multi-writer to write both to file and stdout
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	} else {
		// Set output to stdout only
		log.SetOutput(os.Stdout)
	}

	log.Printf("Logging initialized")
}

func main() {

	flag.Parse()

	config := initializeConfiguration(cfgFile)

	setupLogging(config.Vulntron)

	if config.Vulntron.RunType == "auto" {
		processAutoMode(config)
	} else if config.Vulntron.RunType == "kafka" {
		processKafkaMode()
	} else {
		fmt.Println("Invalid message type. Please use either 'kafka' or 'auto'.")
		os.Exit(1)
	}
}

func initializeConfiguration(filePath string) config.Config {
	config, err := config.ReadConfig(filePath)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		os.Exit(1)
	}
	timeStamp := time.Now().Format("2006-01-02_15-04-05")
	logFileName := fmt.Sprintf("Grype_eng_%s.log", timeStamp)
	config.Vulntron.Logging.LogFileName = logFileName
	return config
}

func initializeDefectDojoClient() (*dd.ClientWithResponses, error) {
	ctx := context.Background()
	ddUsername := os.Getenv("DEFECT_DOJO_USERNAME")
	ddPassword := os.Getenv("DEFECT_DOJO_PASSWORD")
	ddUrl := os.Getenv("DEFECT_DOJO_URL")

	client, err := vulntron_dd.TokenInit(ddUsername, ddPassword, ddUrl, &ctx)
	if err != nil {
		return nil, fmt.Errorf("error initializing DefectDojo client: %v", err)
	}
	return client, nil
}

func processAutoMode(config config.Config) {
	ctx := context.Background()
	client, err := initializeDefectDojoClient()
	if err != nil {
		fmt.Printf("Error initializing DefectDojo client: %v\n", err)
		os.Exit(2)
	}

	ocToken := os.Getenv("OC_TOKEN")
	namespacesString := os.Getenv("OC_NAMESPACE_LIST")
	namespacesRegex := os.Getenv("OC_NAMESPACE_REGEX")

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

	ocNamespaces := processNamespaces(clientset, namespacesString, namespacesRegex)

	allPodInfos := retrievePodInfo(clientset, ocNamespaces)

	updateSystemSettings(&ctx, client, config)

	namespaceProductTypeIds := manageProductTypes(&ctx, client, ocNamespaces)

	scanPod(&ctx, client, allPodInfos, namespaceProductTypeIds, config)

}

func processNamespaces(clientset *kubernetes.Clientset, namespacesString, namespacesRegex string) []string {
	var ocNamespaces []string
	if namespacesRegex != "" {
		regex, err := regexp.Compile(namespacesRegex)
		if err != nil {
			fmt.Printf("Error compiling regex: %v\n", err)
			os.Exit(1)
		}

		namespaceList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("Error listing namespaces: %v\n", err)
			os.Exit(1)
		}

		for _, namespace := range namespaceList.Items {
			if regex.MatchString(namespace.Name) {
				ocNamespaces = append(ocNamespaces, namespace.Name)
			}
		}
	} else {
		ocNamespaces = strings.Split(namespacesString, ",")
	}
	return ocNamespaces
}

func retrievePodInfo(clientset *kubernetes.Clientset, ocNamespaces []string) []PodInfo {
	var allPodInfos []PodInfo

	for _, namespace := range ocNamespaces {
		podList, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("Error listing pods in namespace %s: %v\n", namespace, err)
			continue
		}
		pods := podList.Items

		var podInfos []PodInfo

		for _, pod := range pods {
			var containerInfos []ContainerInfo

			for _, container := range pod.Spec.Containers {
				var containerImageID string
				for _, containerStatus := range pod.Status.ContainerStatuses {
					if containerStatus.Image == container.Image {
						containerImageID = containerStatus.ImageID
					}
				}

				if containerImageID == "" {
					ref, err := name.ParseReference(container.Image)
					if err != nil {
						fmt.Printf("Error parsing image name: %v\n", err)
					} else {
						desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
						if err != nil {
							fmt.Printf("Error fetching image description: %v\n", err)
						} else {
							log.Printf("Digest of the image %s is %s", container.Image, desc.Digest)
							containerImageID = container.Image + "@" + desc.Digest.String()
						}
					}
				}

				if strings.Contains(container.Image, "@") {
					parts := strings.Split(container.Image, "@")
					imageName := parts[0]
					container.Image = imageName
				}

				containerInfo := ContainerInfo{
					Container_Name: container.Name,
					Image:          container.Image,
					ImageID:        strings.ToLower(containerImageID),
				}
				containerInfos = append(containerInfos, containerInfo)
			}

			podInfo := PodInfo{
				Pod_Name:   pod.Name,
				Namespace:  pod.Namespace,
				Containers: containerInfos,
				StartTime:  pod.Status.StartTime.Time.Format("2006-01-02T15:04:05Z"),
			}
			podInfos = append(podInfos, podInfo)
		}

		allPodInfos = append(allPodInfos, podInfos...)
	}

	return allPodInfos
}

func updateSystemSettings(ctx *context.Context, client *dd.ClientWithResponses, config config.Config) {
	systemSettings, err := vulntron_dd.ListSystemSettings(ctx, client)
	if err != nil {
		fmt.Printf("Error getting system settings: %v\n", err)
		os.Exit(1)
	}
	for _, pt := range *systemSettings.Results {
		if pt.MaxDupes == nil ||
			*pt.EnableDeduplication != config.DefectDojo.EnableDeduplication ||
			*pt.DeleteDuplicates != config.DefectDojo.DeleteDuplicates ||
			*pt.MaxDupes != config.DefectDojo.MaxDuplicates {
			log.Printf("Defect Dojo System settings are not correct!")
			err = vulntron_dd.UpdateSystemSettings(
				ctx,
				client,
				*pt.Id,
				config.DefectDojo.EnableDeduplication,
				config.DefectDojo.DeleteDuplicates,
				config.DefectDojo.MaxDuplicates)
			if err != nil {
				fmt.Printf("Error setting system settings: %v\n", err)
				os.Exit(1)
			}
		} else {
			log.Printf("Defect Dojo System settings match config.")
		}
	}
}

func manageProductTypes(ctx *context.Context, client *dd.ClientWithResponses, ocNamespaces []string) map[string]int {
	productTypes, err := vulntron_dd.ListProductTypes(ctx, client)
	if err != nil {
		fmt.Printf("Error getting product types: %v\n", err)
		os.Exit(1)
	}

	namespaceProductTypeIds := make(map[string]int)

	for _, pt := range *productTypes.Results {
		namespaceProductTypeIds[pt.Name] = *pt.Id
	}

	for _, namespace := range ocNamespaces {
		if _, found := namespaceProductTypeIds[namespace]; !found {
			// Product Type does not exist, create it
			productTypeId, err := vulntron_dd.CreateProductType(ctx, client, namespace)
			if err != nil {
				fmt.Printf("Error creating product type for namespace %s: %v\n", namespace, err)
				os.Exit(1)
			}
			// Update the map with the new product type ID
			namespaceProductTypeIds[namespace] = productTypeId
		}
	}

	return namespaceProductTypeIds
}

func scanPod(ctx *context.Context, client *dd.ClientWithResponses, allPodInfos []PodInfo, namespaceProductTypeIds map[string]int, config config.Config) {
	for counter, pod := range allPodInfos {
		log.Printf(" >>>>>>>>>>>>> Checking %d out of %d pods <<<<<<<<<<<<<", counter+1, len(allPodInfos))
		productTypeId := namespaceProductTypeIds[pod.Namespace]

		// Create or find existing Product
		productCreated, productIdInt, err := vulntron_dd.CreateProduct(ctx, client, pod.Pod_Name, productTypeId)
		if err != nil {
			fmt.Printf("Error processing product types: %v\n", err)
			os.Exit(1)
		}
		if !productCreated {
			productIdInt, err = vulntron_dd.ListProducts(ctx, client, pod.Pod_Name)
			if err != nil {
				fmt.Printf("Error listing product types: %v\n", err)
				os.Exit(1)
			}
		}

		// Collect image hashes from source
		uniqueTags := map[string]bool{}
		var original_tags []string
		for _, container := range pod.Containers {
			if !uniqueTags[container.ImageID] {
				original_tags = append(original_tags, strings.ToLower(container.Image))
				uniqueTags[container.ImageID] = true
			}
		}

		// Handle engagements
		engs, err := vulntron_dd.ListEngagements(ctx, client, productIdInt)
		if err != nil {
			fmt.Printf("Error listing engagements using productID: %v\n", err)
			os.Exit(1)
		}

		var engagementFound bool
		var engagementId int
		for _, pt := range *engs.Results {
			if utils.CompareLists(*pt.Tags, original_tags) {
				engagementFound = true
				break
			} else {
				engagementId = *pt.Id
			}
		}

		if engagementFound {
			log.Printf("Engagement with the same image tag already exists, skipping new engagements for pod: %s", pod.Pod_Name)
		} else if engagementId == 0 && !productCreated {
			// No access to image
			log.Printf("There are no tags - Possible no access to image!")

		} else {

			if productCreated {
				log.Printf("No engagements inside the Product - No tags yet")

			} else {
				log.Printf("Tags are not the same")
				log.Printf("Old engagement has tag %d", engagementId)
			}

			if engagementId != 0 {
				if err := vulntron_dd.DeleteEngagement(ctx, client, engagementId); err != nil {
					fmt.Printf("Error deleting old engagement %v\n", err)
					os.Exit(1)
				}
			}
			var containerInfo string
			for _, container := range pod.Containers {
				containerInfo += fmt.Sprintf("%s %s\n", container.Image, container.ImageID)
			}

			if err := vulntron_dd.CreateEngagement(ctx, client, original_tags, productIdInt, containerInfo); err != nil {
				fmt.Printf("Error creating new engagement %v\n", err)
				// TODO handle this gracefully
				// os.Exit(1)
			}

			// Process each container for scanning
			for _, container := range pod.Containers {
				log.Printf("Starting scanning process for: %s", container.Image)
				fmt.Printf("imageID: %v\n", container.ImageID)
				fmt.Printf("image: %v\n", container.Image)

				tests, err := vulntron_dd.ListTests(ctx, client, container.ImageID)
				if err != nil {
					fmt.Printf("Error listing tests using tag: %v\n", err)
					os.Exit(1)
				}

				if *tests.Count > 0 {
					fmt.Println("========= there is already a test with the same tag")

				} else {
					// Run Grype
					_, fileName, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, container.ImageID)
					if err != nil {
						fmt.Printf("Error running Grype for image %s: %v\n", container.Image, err)
						continue
					}

					if err := vulntron_dd.ImportGrypeScan(ctx, client, pod.Namespace, container.Container_Name, container.ImageID, pod.Pod_Name, fileName); err != nil {
						fmt.Printf("Error importing Grype scan %s: %v\n", container.Container_Name, err)
						continue
					}
				}
			}
		}
	}
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

func processKafkaMode() {
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
		// server-side rebalance happens, the consumer session will need to be
		// recreated to get the new claims
		err := group.Consume(*ctx, topic, handler)
		if err != nil {
			panic(err)
		}
	}
}
