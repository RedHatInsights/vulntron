package vulntronauto

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/RedHatInsights/Vulntron/internal/config"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_dd"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_grype"
	vulntronscannerstats "github.com/RedHatInsights/Vulntron/internal/vulntron_scanner_stats"
	"github.com/RedHatInsights/Vulntron/internal/vulntron_trivy"

	dd "github.com/doximity/defect-dojo-client-go"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

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

type ScanType struct {
	Name     string
	EngName  string
	Function func(config.Config, string) (string, error)
	Enabled  bool
}

type ScanFunction func(cfg config.Config, imageID string) (string, error)

var scanFunctionMap = map[string]ScanFunction{
	"RunGrype": vulntron_grype.RunGrype,
	"RunTrivy": vulntron_trivy.RunTrivy,
	// "RunAnotherScanner": vulntron_other.RunAnotherScanner
}

func ProcessAutoMode(config config.Config, ctx *context.Context, client *dd.ClientWithResponses) {

	ocToken := os.Getenv("OC_TOKEN")
	namespacesString := os.Getenv("OC_NAMESPACE_LIST")
	namespacesRegex := os.Getenv("OC_NAMESPACE_REGEX")

	// Create a rest.Config object
	ocConfig := &rest.Config{
		Host:        config.Vulntron.ClusterURL,
		BearerToken: ocToken,
	}

	// Create a Kubernetes clientset using the rest.Config
	clientset, err := kubernetes.NewForConfig(ocConfig)
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
	}

	ocNamespaces := processNamespaces(clientset, namespacesString, namespacesRegex)

	allPodInfos := parseClusterData(clientset, ocNamespaces)

	namespaceProductTypeIds := manageProductTypes(ctx, client, ocNamespaces)

	scanPod(ctx, client, allPodInfos, namespaceProductTypeIds, config)

	log.Print("Scanning complete!")

}

func processNamespaces(clientset *kubernetes.Clientset, namespacesString, namespacesRegex string) []string {
	var ocNamespaces []string
	if namespacesRegex != "" {
		regex, err := regexp.Compile(namespacesRegex)
		if err != nil {
			log.Fatalf("Error compiling regex: %v", err)
		}

		namespaceList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Fatalf("Error listing namespaces: %v", err)
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

func parseClusterData(clientset *kubernetes.Clientset, ocNamespaces []string) []PodInfo {
	var allPodInfos []PodInfo

	for _, namespace := range ocNamespaces {
		podList, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Printf("Error listing pods in namespace %s: %v\n", namespace, err)
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
						log.Printf("Error parsing image name: %v\n", err)
					} else {
						desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
						if err != nil {
							log.Printf("Error fetching image description: %v\n", err)
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

func manageProductTypes(ctx *context.Context, client *dd.ClientWithResponses, ocNamespaces []string) map[string]int {
	productTypes, err := vulntron_dd.ListProductTypes(ctx, client)
	if err != nil {
		log.Fatalf("Error getting product types: %v", err)
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
				log.Fatalf("Error creating product type for namespace %s: %v", namespace, err)
			}
			// Update the map with the new product type ID
			namespaceProductTypeIds[namespace] = productTypeId
		}
	}
	return namespaceProductTypeIds
}

// Initializes scan types from the configuration
func loadScanTypes(cfg config.Config) []ScanType {
	var scanTypes []ScanType
	for _, sc := range cfg.Scan {
		function := getScanFunction(sc.Function)
		if function != nil {
			scanTypes = append(scanTypes, ScanType{
				Name:     sc.Name,
				EngName:  sc.EngName,
				Function: function,
				Enabled:  sc.Enabled,
			})
		}
	}
	return scanTypes
}

func getScanFunction(name string) ScanFunction {
	if function, exists := scanFunctionMap[name]; exists {
		return function
	}
	return nil
}

func scanPod(ctx *context.Context, client *dd.ClientWithResponses, allPodInfos []PodInfo, namespaceProductTypeIds map[string]int, config config.Config) {
	scannerStats := vulntronscannerstats.NewScannerStats()

	// Initialize scan types from config
	scanTypes := loadScanTypes(config)

	for counter, pod := range allPodInfos {
		log.Printf(" >>>>>>>>>>>>> Checking %d out of %d pods <<<<<<<<<<<<<", counter+1, len(allPodInfos))
		log.Printf("Checking pod %s in namespace %s for scans", pod.Pod_Name, pod.Namespace)
		scannerStats.PodsScanned++
		productTypeId := namespaceProductTypeIds[pod.Namespace]
		_, productIdInt, err := vulntron_dd.CreateProduct(ctx, client, pod.Pod_Name, productTypeId)
		if err != nil {
			log.Fatalf("Error processing product types: %v", err)
		}

		// Create or use existing engagements for each scan type
		for _, scanType := range scanTypes {
			if scanType.Enabled {
				manageEngagementForScanType(ctx, client, pod, productIdInt, scanType, config, scannerStats)
			}
		}
	}
	scannerStats.ScanningTools = len(scanTypes)
	scannerStats.Finish()
	scannerStats.Print()
}

func manageEngagementForScanType(ctx *context.Context, client *dd.ClientWithResponses, pod PodInfo, productIdInt int, scanType ScanType, config config.Config, scannerStats *vulntronscannerstats.ScannerStats) {
	// Gather all image IDs for a collective engagement description
	var containerInfo strings.Builder
	var images []string
	for _, container := range pod.Containers {
		scannerStats.ImagesScanned++
		containerInfo.WriteString(fmt.Sprintf("%s (%s)\n", container.Image, container.ImageID))
		images = append(images, container.Image)
	}

	// Check for existing engagement specifically for this scan type
	engagements, err := vulntron_dd.ListEngagements(ctx, client, productIdInt)
	if err != nil {
		log.Fatalf("Error listing engagements: %v", err)
	}

	var engagementIdForScan int
	for _, engagement := range *engagements.Results {
		if *engagement.Name == scanType.EngName {
			engagementIdForScan = *engagement.Id
			break
		}
	}

	if engagementIdForScan == 0 {
		// Create a new engagement if not found
		if err := vulntron_dd.CreateEngagement(ctx, client, images, productIdInt, containerInfo.String(), scanType.EngName); err != nil {
			log.Fatalf("Error creating new engagement for scan type %s: %v", scanType.Name, err)
		}
	} else {
		// Update the existing engagement if necessary
		log.Printf("Using existing engagement ID %d for scan type %s", engagementIdForScan, scanType.Name)
	}

	// Handle scanning for each image within the single engagement
	for _, container := range pod.Containers {
		scanImage(ctx, client, container, pod, scanType, config)
	}
}

func scanImage(ctx *context.Context, client *dd.ClientWithResponses, container ContainerInfo, pod PodInfo, scanType ScanType, config config.Config) {
	tests, err := vulntron_dd.ListTests(ctx, client, container.ImageID)
	if err != nil {
		log.Fatalf("Error listing tests: %v", err)
	}

	// Check if a test already exists for this image and scan type
	for _, test := range *tests.Results {
		if *test.ScanType == scanType.Name && contains(*test.Tags, container.ImageID) {
			log.Printf("Test using %s type already exists for image %s with ID %s, skipping", *test.ScanType, container.Image, container.ImageID)
			return
		}
	}

	// If no test exists, proceed with scanning
	log.Printf("Running scan type %s for image %s", scanType.Name, container.Image)
	fileName, err := scanType.Function(config, container.ImageID)
	if err != nil {
		log.Printf("Error running scan %s for image %s: %v", scanType.Name, container.Image, err)
		return
	}

	if err := vulntron_dd.ImportScan(ctx, client, pod.Namespace, container.Container_Name, container.ImageID, pod.Pod_Name, fileName, scanType.Name, scanType.EngName); err != nil {
		log.Printf("Error importing scan result for image %s: %v", container.Image, err)
	}
}

// Utility function to check if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
