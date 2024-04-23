package vulntron_dd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	dd "github.com/doximity/defect-dojo-client-go"
)

// TokenInit creates a new DefectDojo client and authenticates using API tokens.
func TokenInit(username, password, url string, ctx *context.Context) (*dd.ClientWithResponses, error) {
	if username == "" || password == "" {
		log.Printf("Username or password is empty")
		return nil, fmt.Errorf("username or password is empty")
	}

	// Create a new DefectDojo client
	tokenClient, err := dd.NewClientWithResponses(url)
	if err != nil {
		log.Printf("Error instantiating the client: %v", err)
		return nil, fmt.Errorf("error instantiating the client: %w", err)
	}

	// Create an API token with username and password
	tokenResponse, err := tokenClient.ApiTokenAuthCreateWithResponse(*ctx, dd.ApiTokenAuthCreateJSONRequestBody{
		Username: &username,
		Password: &password,
	})
	if err != nil {
		log.Printf("Error creating API token: %v", err)
		return nil, fmt.Errorf("error creating API token: %w", err)
	}
	if tokenResponse.StatusCode() != http.StatusOK {
		log.Printf("Unexpected status code creating token: %d", tokenResponse.StatusCode())
		return nil, fmt.Errorf("unexpected status code creating token: %d", tokenResponse.StatusCode())
	}

	// Decode the response body to get the auth token
	var authToken dd.AuthToken
	if err := json.Unmarshal(tokenResponse.Body, &authToken); err != nil {
		log.Printf("Error decoding JSON response: %v", err)
		return nil, fmt.Errorf("error decoding JSON response: %w", err)
	}
	if authToken.Token == nil {
		log.Printf("Token not present in the response")
		return nil, fmt.Errorf("token not present in the response")
	}

	// Create a security provider with the token
	tokenProvider, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", fmt.Sprintf("Token %s", *authToken.Token))
	if err != nil {
		log.Printf("Error setting up token provider: %v", err)
		return nil, fmt.Errorf("error setting up token provider: %w", err)
	}

	// Create a new client with the token provider
	client, err := dd.NewClientWithResponses(url, dd.WithRequestEditorFn(tokenProvider.Intercept))
	if err != nil {
		log.Printf("Error setting up client API: %v", err)
		return nil, fmt.Errorf("error setting up client API: %w", err)
	}

	return client, nil
}

func ListProductTypes(ctx *context.Context, client *dd.ClientWithResponses) (*dd.PaginatedProductTypeList, error) {
	// List product types
	limit := 1000
	apiRespProductType, err := client.ProductTypesListWithResponse(*ctx, &dd.ProductTypesListParams{Limit: &limit})
	if err != nil {
		log.Printf("Error listing product types: %v", err)
		return nil, fmt.Errorf("error listing product types: %w", err)
	}

	// Check response status code
	if apiRespProductType.StatusCode() != http.StatusOK {
		log.Printf("Unexpected status code listing product types: %d", apiRespProductType.StatusCode())
		return nil, fmt.Errorf("unexpected status code listing product types: %d", apiRespProductType.StatusCode())
	}

	// Unmarshal the JSON response into the ProductTypes variable
	var ProductTypes dd.PaginatedProductTypeList
	if err := json.Unmarshal(apiRespProductType.Body, &ProductTypes); err != nil {
		log.Printf("Error decoding JSON response: %v", err)
		return nil, fmt.Errorf("error decoding JSON response: %w", err)
	}

	return &ProductTypes, nil
}

func CreateProductType(ctx *context.Context, client *dd.ClientWithResponses, nameSpace string) (int, error) {
	productTypeDesc := "Sample description for the product type"

	// Create a product type
	apiResp, err := client.ProductTypesCreateWithResponse(*ctx, dd.ProductTypesCreateJSONRequestBody{
		Name:            nameSpace,
		Description:     &productTypeDesc,
		CriticalProduct: nil,
		KeyProduct:      nil,
	})
	if err != nil {
		log.Printf("Error creating product type: %v", err)
		return 0, fmt.Errorf("error creating product type: %w", err)
	}

	// Check if the status code indicates the product type was successfully created
	if apiResp.StatusCode() != http.StatusCreated {
		log.Printf("Product Type not created. Status code: %d", apiResp.StatusCode())
		return 0, fmt.Errorf("product type not created, received status code: %d", apiResp.StatusCode())
	}

	// Decode the response body into the productTypeResp struct
	var productTypeResp dd.ProductType
	if err := json.Unmarshal(apiResp.Body, &productTypeResp); err != nil {
		log.Printf("Error decoding JSON for product type: %v", err)
		return 0, fmt.Errorf("error decoding JSON for product type: %w", err)
	}

	log.Printf("Product Type %s created with ID %d", productTypeResp.Name, *productTypeResp.Id)

	return *productTypeResp.Id, nil
}

func CreateProduct(ctx *context.Context, client *dd.ClientWithResponses, podName string, productTypeID int) (bool, int, error) {
	// Attempt to create a new product with the provided name, description, and product type ID
	apiResp, err := client.ProductsCreateWithResponse(*ctx, dd.ProductsCreateJSONRequestBody{
		Name:        podName,
		Description: "Sample description product", // TODO: Update with a real description if necessary
		ProdType:    productTypeID,
	})
	if err != nil {
		log.Printf("Error creating product for pod '%s': %v", podName, err)
		return false, 0, fmt.Errorf("error creating product: %w", err)
	}

	// Handle the response based on the status code
	switch apiResp.StatusCode() {
	case http.StatusBadRequest:
		log.Printf("Product: '%s' already exists, skipping Product creation!", podName)
		productIdInt, err := ListProducts(ctx, client, podName)
		if err != nil {
			log.Fatalf("Error listing products: %v", err)
		}
		return false, productIdInt, nil

	case http.StatusCreated:
		var productResponse dd.Product
		if err := json.Unmarshal(apiResp.Body, &productResponse); err != nil {
			log.Printf("Failed to decode product response for pod '%s': %v", podName, err)
			return false, 0, fmt.Errorf("failed to decode product response: %w", err)
		}
		log.Printf("New product created with ID %d and name '%s'", *productResponse.Id, productResponse.Name)
		return true, *productResponse.Id, nil
	default:
		errMsg := fmt.Sprintf("Received unexpected status code %d while creating product for pod '%s'", apiResp.StatusCode(), podName)
		log.Printf("%v", errMsg)
		return false, 0, fmt.Errorf(errMsg)
	}
}

func ListProducts(ctx *context.Context, client *dd.ClientWithResponses, productName string) (int, error) {
	// List products
	apiResp, err := client.ProductsListWithResponse(*ctx, &dd.ProductsListParams{
		Name: &productName,
	})
	if err != nil {
		log.Printf("Error listing products: %v", err)
		return 0, fmt.Errorf("failed to list products: %w", err)
	}

	if apiResp.StatusCode() != http.StatusOK {
		log.Printf("Unexpected status code when listing products: %d", apiResp.StatusCode())
		return 0, fmt.Errorf("unexpected status code %d when listing products", apiResp.StatusCode())
	}

	// Decode the response body into products struct
	var products dd.PaginatedProductList
	if err := json.Unmarshal(apiResp.Body, &products); err != nil {
		log.Printf("Error decoding product list response: %v", err)
		return 0, fmt.Errorf("failed to decode product list response: %w", err)
	}

	// Check the count of products and handle accordingly
	switch count := *products.Count; count {
	case 1:
		product := (*products.Results)[0]
		log.Printf("Product '%s' has id %d", productName, *product.Id)
		return *product.Id, nil
	case 0:
		log.Printf("No products found for: %s", productName)
		return 0, fmt.Errorf("no products returned for %s", productName)
	default:
		log.Printf("Multiple products found with the same name: %s", productName)
		return 0, fmt.Errorf("more than one product with the same name exists")
	}
}

func ListEngagements(ctx *context.Context, client *dd.ClientWithResponses, productId int) (*dd.PaginatedEngagementList, error) {
	var engagements dd.PaginatedEngagementList

	// List engagements for the given product
	resp, err := client.EngagementsListWithResponse(*ctx, &dd.EngagementsListParams{
		Product: &productId,
	})
	if err != nil {
		log.Printf("Failed to list engagements: %v", err)
		return nil, fmt.Errorf("failed to list engagements: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		log.Printf("Error fetching engagements, status code: %d, response: %s", resp.StatusCode(), string(resp.Body))
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	// Decode the response body into the engagements struct
	if err := json.Unmarshal(resp.Body, &engagements); err != nil {
		log.Printf("Error decoding JSON response: %v", err)
		return nil, fmt.Errorf("error decoding JSON response: %w", err)
	}

	log.Printf("Successfully listed engagements for productId %d", productId)
	return &engagements, nil
}

func ListTests(ctx *context.Context, client *dd.ClientWithResponses, imageTag string) (*dd.PaginatedTestList, error) {
	var tests dd.PaginatedTestList

	// List tests based on the provided image tag
	resp, err := client.TestsListWithResponse(*ctx, &dd.TestsListParams{
		Tag: &imageTag,
	})
	if err != nil {
		log.Printf("Error listing tests for tag %s: %v", imageTag, err)
		return nil, fmt.Errorf("failed to list tests for tag %s: %w", imageTag, err)
	}

	// Check the response status code
	if resp.StatusCode() != http.StatusOK {
		log.Printf("Error in fetching tests for tag %s, received status code: %d", imageTag, resp.StatusCode())
		return nil, fmt.Errorf("unexpected status code when fetching tests for tag %s: %d", imageTag, resp.StatusCode())
	}

	// Decode the response body to extract tests
	if err := json.Unmarshal(resp.Body, &tests); err != nil {
		log.Printf("Error decoding JSON response for tests listing: %v", err)
		return nil, fmt.Errorf("error decoding JSON response for tests listing: %w", err)
	}

	log.Printf("Successfully listed tests for tag %s", imageTag)
	return &tests, nil
}

func CreateEngagement(ctx *context.Context, client *dd.ClientWithResponses, containers []string, productId int, desc string, engName string) error {
	// Prepare the request body
	requestBody := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(requestBody)
	defer multipartWriter.Close()

	// Add fields to the request body for each container and additional metadata
	for _, container := range containers {
		if err := multipartWriter.WriteField("tags", container); err != nil {
			log.Printf("Error adding tags to request: %v", err)
			return fmt.Errorf("error adding tags to request: %w", err)
		}
	}

	// Additional engagement details
	fields := map[string]string{
		"product":                     strconv.Itoa(productId),
		"target_start":                time.Now().Format("2006-01-02"),
		"target_end":                  time.Now().Format("2006-01-02"),
		"name":                        engName,
		"deduplication_on_engagement": "true",
		"description":                 desc,
	}

	for key, value := range fields {
		if err := multipartWriter.WriteField(key, value); err != nil {
			log.Printf("Error adding field %s: %v", key, err)
			return fmt.Errorf("error adding field %s: %w", key, err)
		}
	}

	// Close the writer to finalize the multipart body
	if err := multipartWriter.Close(); err != nil {
		log.Printf("Error closing multipart writer: %v", err)
		return fmt.Errorf("error closing multipart writer: %w", err)
	}

	// Create the engagement
	response, err := client.EngagementsCreateWithBodyWithResponse(*ctx, multipartWriter.FormDataContentType(), requestBody)
	if err != nil {
		log.Printf("Error creating engagement API call: %v", err)
		return fmt.Errorf("error creating engagement API call: %w", err)
	}

	// Check if the engagement was successfully created
	if response.StatusCode() != http.StatusCreated {
		log.Printf("Engagement not created. Status code: %d, Response: %s", response.StatusCode(), string(response.Body))
		return fmt.Errorf("engagement not created, received status code: %d", response.StatusCode())
	}

	log.Printf("Engagement successfully created for ProductID %d", productId)
	return nil
}

func DeleteEngagement(ctx *context.Context, client *dd.ClientWithResponses, engagementID int) error {
	// Attempt to delete the engagement
	resp, err := client.EngagementsDestroyWithResponse(*ctx, engagementID)
	if err != nil {
		log.Printf("Failed to delete engagement %d: %v", engagementID, err)
		return fmt.Errorf("failed to delete engagement: %w", err)
	}

	// Check if the engagement was successfully deleted
	if resp.StatusCode() != http.StatusNoContent {
		log.Printf("Engagement %d not deleted: %s", engagementID, string(resp.Body))
		return fmt.Errorf("engagement not deleted, received status code: %d", resp.StatusCode())
	}

	log.Printf("Engagement %d deleted", engagementID)
	return nil
}

func ImportScan(
	ctx *context.Context,
	client *dd.ClientWithResponses,
	namespace, containerName, imageID, podName, fileName string, scanType string, engName string,
) error {
	// Initialize multipart writer to build the body for the POST request
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if imageID == "" {
		imageID = "unknown"
	}

	// Populate the body with fields required by the API for scan import
	formFields := map[string]string{
		"product_type_name":                      namespace,
		"active":                                 "true",
		"verified":                               "true",
		"close_old_findings":                     "true",
		"test_title":                             containerName,
		"engagement_name":                        engName,
		"build_id":                               "",
		"deduplication_on_engagement":            "true",
		"push_to_jira":                           "false",
		"minimum_severity":                       "Info",
		"close_old_findings_product_scope":       "true",
		"scan_date":                              time.Now().Format("2006-01-02"),
		"create_finding_groups_for_all_findings": "false",
		"engagement_end_date":                    "",
		"tags":                                   imageID,
		"product_name":                           podName,
		"auto_create_context":                    "true",
		"scan_type":                              scanType,
	}

	for key, value := range formFields {
		if err := writer.WriteField(key, value); err != nil {
			log.Printf("Error adding field %s: %v", key, err)
			return fmt.Errorf("error adding field %s: %w", key, err)
		}
	}

	// Add the scan result file to the request
	file, err := os.Open(fileName)
	if err != nil {
		log.Printf("Error opening file %s: %v", fileName, err)
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		log.Printf("Error creating form file for %s: %v", fileName, err)
		return fmt.Errorf("error creating form file: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		log.Printf("Error copying file content for %s: %v", fileName, err)
		return fmt.Errorf("error copying file content: %w", err)
	}

	// Ensure all parts are written to the buffer
	if err := writer.Close(); err != nil {
		log.Printf("Error closing multipart writer for %s: %v", fileName, err)
		return fmt.Errorf("error closing multipart writer: %w", err)
	}

	// Send the import scan request to the server
	apiResp, err := client.ImportScanCreateWithBodyWithResponse(*ctx, writer.FormDataContentType(), body)
	if err != nil {
		log.Printf("Error sending request to import scan for %s: %v", fileName, err)
		return fmt.Errorf("error sending request: %w", err)
	}

	// Check the response from the API
	if apiResp.StatusCode() != http.StatusCreated {
		log.Printf("Scan import failed for %s: %s", fileName, string(apiResp.Body))
		return fmt.Errorf("error in importing scan: %s", string(apiResp.Body))
	}

	log.Printf("Scan for %s imported successfully!", fileName)
	return nil
}

func ListSystemSettings(ctx *context.Context, client *dd.ClientWithResponses) (*dd.PaginatedSystemSettingsList, error) {
	var systemSettings dd.PaginatedSystemSettingsList

	// Get system settings
	apiResp, err := client.SystemSettingsListWithResponse(*ctx, &dd.SystemSettingsListParams{})
	if err != nil {
		log.Printf("Error getting system settings: %v", err)
		return nil, fmt.Errorf("error getting system settings: %w", err)
	}

	if apiResp.StatusCode() != http.StatusOK {
		log.Printf("Unexpected status code received: %d", apiResp.StatusCode())
		return nil, fmt.Errorf("unexpected status code: %d", apiResp.StatusCode())
	}

	// Decode the response body
	if err = json.Unmarshal(apiResp.Body, &systemSettings); err != nil {
		log.Printf("Error decoding JSON response: %v", err)
		return nil, fmt.Errorf("error decoding JSON response: %w", err)
	}

	return &systemSettings, nil
}

func UpdateSystemSettings(ctx *context.Context, client *dd.ClientWithResponses, id int, enableDeduplication bool, deleteDuplicates bool, maxDuplicates int) error {
	// Prepare request body
	settingsUpdate := dd.SystemSettingsUpdateJSONRequestBody{
		EnableDeduplication: &enableDeduplication,
		DeleteDuplicates:    &deleteDuplicates,
		MaxDupes:            &maxDuplicates,
	}

	// Update system settings
	apiResp, err := client.SystemSettingsUpdateWithResponse(*ctx, id, settingsUpdate)
	if err != nil {
		log.Printf("Error updating system settings: %v", err)
		return fmt.Errorf("error updating system settings: %w", err)
	}

	if apiResp.StatusCode() != http.StatusOK {
		log.Printf("Unexpected status code during update: %d", apiResp.StatusCode())
		return fmt.Errorf("unexpected status code: %d", apiResp.StatusCode())
	}

	log.Printf("System settings for profile %d updated successfully.", id)
	return nil
}

func DeleteProductTypes(ctx *context.Context, client *dd.ClientWithResponses) error {
	// List all product types to get their IDs
	productTypes, err := ListProductTypes(ctx, client)
	if err != nil {
		log.Printf("Failed to list product types: %v", err)
		return fmt.Errorf("failed to list product types: %w", err)
	}

	log.Printf("Starting deleting product types...")
	// Iterate over the list of product types and delete each one
	for _, productType := range *productTypes.Results {
		resp, err := client.ProductTypesDestroyWithResponse(*ctx, *productType.Id)
		if err != nil {
			log.Printf("Failed to delete product type with ID %d: %v", *productType.Id, err)
			return fmt.Errorf("failed to delete product type with ID %d: %w", *productType.Id, err)
		}
		if resp.StatusCode() != http.StatusNoContent {
			log.Printf("Failed to delete product type with ID %d: received status code %d", *productType.Id, resp.StatusCode())
			return fmt.Errorf("failed to delete product type with ID %d, received status code: %d", *productType.Id, resp.StatusCode())
		}
		log.Printf("Product type with ID %d deleted successfully", *productType.Id)
	}

	log.Printf("All product types deleted successfully")
	return nil
}
