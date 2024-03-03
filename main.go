package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_grype"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_syft"
	dd "github.com/doximity/defect-dojo-client-go"

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

func compareLists(list1, list2 []string) bool {
	// Create maps to store the counts of occurrences for each list
	countMap1 := make(map[string]int)
	countMap2 := make(map[string]int)

	// Populate count maps for list1
	for _, item := range list1 {
		countMap1[item]++
	}

	// Populate count maps for list2
	for _, item := range list2 {
		countMap2[item]++
	}

	// Check if the counts match for each item
	for item, count := range countMap1 {
		if countMap2[item] != count {
			return false
		}
	}

	// Check if both lists contain the same unique elements
	return len(countMap1) == len(countMap2)
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

	// TODO check DD config, set deduplicaion, etc.

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

	ctx := context.Background()

	var ProductTypeId int

	// token := os.Getenv("DOJO_APIKEY")
	// token := "2db228fe58cace5f75cd53cb7b8c91304e9a4291"

	client, err := vulntron_dd.TokenInit(config.DefectDojo.UserName, config.DefectDojo.Password, config.DefectDojo.Token, config.DefectDojo.Url, &ctx)
	if err != nil {
		fmt.Println("Error getting client:", err)
		os.Exit(1)
	}

	// Check the value of the -type flag
	switch runType {

	// TODO move to config
	case "auto":
		utils.DebugPrint("Selected message type: Auto")

		var json_file_input bool = true
		var pods []v1.Pod

		if json_file_input {
			// Read the JSON file
			jsonFile, err := os.ReadFile("/home/michal/Documents/Personal/School/DIP/vulntron/ee_comp.json")
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

		} else {

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
			podList, err := clientset.CoreV1().Pods(config.Loader.Namespace).List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				fmt.Printf("Error listing pods: %v\n", err)
				os.Exit(1)
			}
			pods = podList.Items

		}

		// Create a slice to hold the PodInfo objects
		var podInfos []PodInfo

		// Iterate through each pod and populate the PodInfo structure
		for _, pod := range pods {
			if pod.Name != "ahoj" { //}== "env-ephemeral-jngktw-mbop-6cbd9c97c6-5zgjf" {
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

		/*
			// Convert podInfos to JSON
			podsJSON, err := json.MarshalIndent(podInfos, "", "  ")
			if err != nil {
				fmt.Printf("Error marshaling podInfos to JSON: %v\n", err)
				os.Exit(1)
			}

			res, err := utils.PrettyString(string(podsJSON))
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(res)
			os.Exit(8)
		*/

		// Check if all namespaces are the same as the one specified in config
		expectedNamespace := config.Loader.Namespace
		for _, podInfo := range podInfos {
			if podInfo.Namespace != expectedNamespace {
				fmt.Printf("Error: Namespace mismatch in pod %s. Expected: %s, Actual: %s\n", podInfo.Pod_Name, expectedNamespace, podInfo.Namespace)
				os.Exit(1)
			}
		}

		// List all Products(namespaces) in current DD deployment
		productTypes, err := vulntron_dd.ListProductTypes(&ctx, client)
		if err != nil {
			fmt.Printf("Error getting product types: %v\n", err)
			os.Exit(1)
		}

		found := false
		for _, pt := range *productTypes.Results {
			if pt.Name == config.Loader.Namespace {
				found = true
				ProductTypeId = *pt.Id
				break
			}
		}

		// create new Product Type (namespace name) if doesn't exist already
		if !found {

			ProductTypeId, err = vulntron_dd.CreateProductType(&ctx, client, config.Loader.Namespace)
			if err != nil {
				fmt.Printf("Error getting product types: %v\n", err)
				os.Exit(1)
			}

		}

		var ProductIdInt int

		// create new tag for current scan and engagement
		for _, pod := range podInfos {

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
			for _, container := range pod.Containers {
				original_tags = append(original_tags, container.ImageID)
			}

			engs, err := vulntron_dd.ListEngagements(&ctx, client, ProductIdInt)
			if err != nil {
				fmt.Printf("Error Listing engagments in product: %v\n", err)
				os.Exit(1)
			}

			var engagement_found bool = false
			for _, pt := range *engs.Results {
				var engagement_tags []string
				engagement_tags = append(engagement_tags, *pt.Tags...)
				if compareLists(engagement_tags, original_tags) {
					engagement_found = true
					break
				}
			}

			if engagement_found {
				utils.DebugPrint("Tags are the same, skipping new engagements for pod: %s", pod.Pod_Name)
				break

			} else {
				utils.DebugPrint("Tags are not the same or there are no tags")

				err = vulntron_dd.CreateEngagement(&ctx, client, original_tags, ProductIdInt)
				if err != nil {
					fmt.Printf("Error Creating new engagement %v\n", err)
					os.Exit(1)
				}

			}

			for _, container := range pod.Containers {
				utils.DebugPrint("Starting scanning process for: %s", container.Image)

				// Run Grype
				_, fileName, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, container.Image)
				if err != nil {
					fmt.Printf("Error running Grype for image %s: %v\n", container.Image, err)
					continue
				}

				// TODO - automate or create MR into Defectdojo
				// https://github.com/DefectDojo/django-DefectDojo/issues/9618
				cmd := exec.Command("python", "severity_fixer.py", fileName)
				_, err = cmd.CombinedOutput()
				if err != nil {
					fmt.Println("Error in fixing file:", err)
					return
				}

				err = vulntron_dd.ImportGrypeScan(&ctx, client, config.Loader.Namespace, container.Container_Name, container.ImageID, pod.Pod_Name, fileName)
				if err != nil {
					fmt.Printf("Error importing Grype scan %s: %v\n", container.Container_Name, err)
					continue
				}

			}

			//break

		}

		os.Exit(7)

		// Loop through each pod and run Syft and Grype for each container's image
		for _, pod := range podInfos {
			for _, container := range pod.Containers {

				fmt.Println(container.Image)
				// Run Syft

				syftOutput, err := vulntron_syft.RunSyft(config.Vulntron, container.Image)
				if err != nil {
					fmt.Printf("Error running Syft for image %s: %v\n", container.Image, err)
					continue
				}

				// Run Grype
				grypeOutput, _, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, container.Image)
				if err != nil {
					fmt.Printf("Error running Grype for image %s: %v\n", container.Image, err)
					continue
				}

				// Insert the results into the database
				if container.StartTime == "" || container.Image == "" || container.Container_Name == "" || grypeOutput == "" || syftOutput == "" {
					fmt.Println("Error: Database insert has missing fields.")
				} else {
					_, err = db.Exec("INSERT INTO deployments (image_name, deployment_date, scan_date, component_name, syft_output, grype_output) VALUES ($1, $2, $3, $4, $5, $6)",
						container.Image, container.StartTime, time.Now().UTC().Format("2006-01-02T15:04:05Z"), container.Container_Name, syftOutput, grypeOutput)
					if err != nil {
						fmt.Printf("Error inserting into the database for image %s: %v\n", container.Image, err)
					}
				}
			}
		}

	case "single":
		utils.DebugPrint("Selected message type: Single")

		imageTag := imageName

		/* 		apiResp, err := client.ProductsCreateWithResponse(ctx, dd.ProductsCreateJSONRequestBody{
			Name:        "My Product",
			Description: "A description",
			ProdType:    1,
		}) */

		var api_testing = false
		if api_testing {
			apiResp, err := client.ConfigurationPermissionsListWithResponse(ctx, &dd.ConfigurationPermissionsListParams{})
			if err != nil {
				fmt.Println("Error testing API:", err)
				os.Exit(1)
			}

			if apiResp.StatusCode() == 200 {
				config_perm := apiResp.Body
				fmt.Println(string(config_perm))
			}
		}

		apiRespProductType, err := client.ProductTypesListWithResponse(ctx, &dd.ProductTypesListParams{})
		if err != nil {
			fmt.Println("Error testing API:", err)
			os.Exit(1)
		}

		if apiRespProductType.StatusCode() == 200 {
			product_type := apiRespProductType.Body
			res, err := utils.PrettyString(string(product_type))
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(res)
		}

		// Run grype
		grypeOutput, _, err := vulntron_grype.RunGrype(config.Grype, config.Vulntron, imageTag)
		if err != nil {
			fmt.Println("Error running Grype:", err)
			os.Exit(1)
		}

		os.Exit(1)

		// Run syft
		syftOutput, err := vulntron_syft.RunSyft(config.Vulntron, imageTag)
		if err != nil {
			fmt.Println("Error running Syft:", err)
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

}
