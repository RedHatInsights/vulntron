package vulntron_dd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/RedHatInsights/Vulntron/internal/utils"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	dd "github.com/doximity/defect-dojo-client-go"
)

func TokenInit(username string, password string, url string, ctx *context.Context) (*dd.ClientWithResponses, error) {

	var authToken dd.AuthToken

	if username != "" && password != "" {
		// Create a new DefectDojo client
		tokenclient, err := dd.NewClientWithResponses(url)
		if err != nil {
			return nil, fmt.Errorf("error: Error instantiating the client: %w", err)
		}

		// Create an API token with username and password
		tokenResponse, err := tokenclient.ApiTokenAuthCreateWithResponse(*ctx, dd.ApiTokenAuthCreateJSONRequestBody{
			Username: &username,
			Password: &password,
		})
		if err != nil {
			return nil, fmt.Errorf("error: Error Creating API token: %w", err)
		}

		// Check response status code
		if tokenResponse.StatusCode() != http.StatusOK {
			return nil, fmt.Errorf("error: Unexpected status code creating token: %d", tokenResponse.StatusCode())
		}

		// Decode the response body
		err = json.Unmarshal(tokenResponse.Body, &authToken)
		if err != nil {
			return nil, fmt.Errorf("error: Decoding JSON response: %w", err)
		}

		// Check if token is present
		if authToken.Token == nil {
			return nil, fmt.Errorf("error: Token not present in the response")
		}
	}

	// Create a security provider with the token
	tokenProvider, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", fmt.Sprintf("Token %s", *authToken.Token))
	if err != nil {
		return nil, fmt.Errorf("error: Error setting up token provider: %w", err)
	}

	// Create a new client with the token provider
	client, err := dd.NewClientWithResponses(url, dd.WithRequestEditorFn(tokenProvider.Intercept))
	if err != nil {
		return nil, fmt.Errorf("error: Error setting up client API: %w", err)
	}

	return client, nil
}

func ListProductTypes(ctx *context.Context, client *dd.ClientWithResponses) (*dd.PaginatedProductTypeList, error) {
	// List product types
	apiRespProductType, err := client.ProductTypesListWithResponse(*ctx, &dd.ProductTypesListParams{})
	if err != nil {
		return nil, fmt.Errorf("error: Listing Product Types: %w", err)
	}

	// Check response status code
	if apiRespProductType.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("error: Unexpected status code listing product types: %d", apiRespProductType.StatusCode())
	}

	// Unmarshal the JSON response into the ProductTypes variable
	var ProductTypes dd.PaginatedProductTypeList
	if err := json.Unmarshal(apiRespProductType.Body, &ProductTypes); err != nil {
		return nil, fmt.Errorf("error: Decoding JSON response: %w", err)
	}

	return &ProductTypes, nil
}

func CreateProductType(ctx *context.Context, client *dd.ClientWithResponses, nameSpace string) (int, error) {

	// Variable to store the response body
	var productTypeResp dd.ProductType
	productTypeDesc := "Sample description for the product type"

	// Create a product type
	apiResp, err := client.ProductTypesCreateWithResponse(*ctx, dd.ProductTypesCreateJSONRequestBody{
		Name:            nameSpace,
		Description:     &productTypeDesc,
		CriticalProduct: nil,
		KeyProduct:      nil,
	})
	if err != nil {
		return 0, fmt.Errorf("error: %w", err)
	}

	// Check if the status code of the response is not 201 (Created)
	if apiResp.StatusCode() != http.StatusCreated {
		return 0, fmt.Errorf("error: Product Type not created. Status code: %d", apiResp.StatusCode())
	}

	utils.DebugPrint("Product Type Created:", string(apiResp.Body))

	// Decode the response body into productTypeResp struct
	err = json.Unmarshal(apiResp.Body, &productTypeResp)
	if err != nil {
		return 0, fmt.Errorf("error: Decoding JSON: %w", err)
	}

	return *productTypeResp.Id, nil
}

func CreateProduct(ctx *context.Context, client *dd.ClientWithResponses, podName string, productTypeID int) (bool, int, error) {
	var productResponse dd.Product

	// Create a new product with the provided name, description, and product type ID
	apiResp, err := client.ProductsCreateWithResponse(*ctx, dd.ProductsCreateJSONRequestBody{
		Name:        podName,
		Description: "Sample description product", // TODO: Fix description
		ProdType:    productTypeID,
	})
	if err != nil {
		return false, 0, fmt.Errorf("failed to create product: %w", err)
	}

	// Check if the product already exists
	switch apiResp.StatusCode() {
	case http.StatusBadRequest:
		utils.DebugPrint("Product: %s already exists, skipping!", podName)
		return false, 0, nil

	// Check if the product was successfully created
	case http.StatusCreated:
		if err := json.Unmarshal(apiResp.Body, &productResponse); err != nil {
			return false, 0, fmt.Errorf("failed to decode product response: %w", err)
		}
		utils.DebugPrint("New Product Created with id: %d and name: %s", *productResponse.Id, productResponse.Name)
		return true, *productResponse.Id, nil

	// Handle other unexpected status codes
	default:
		fmt.Println("Error:", string(apiResp.Body))
		return false, 0, fmt.Errorf("unexpected status code: %d, response: %s", apiResp.StatusCode(), string(apiResp.Body))
	}
}

func ListProducts(ctx *context.Context, client *dd.ClientWithResponses, productName string) (int, error) {
	var products dd.PaginatedProductList

	// List products
	apiResp, err := client.ProductsListWithResponse(*ctx, &dd.ProductsListParams{
		Name: &productName,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list products: %w", err)
	}

	// Check response status code
	switch apiResp.StatusCode() {
	case http.StatusOK:
		// Unmarshal the response body
		if err := json.Unmarshal(apiResp.Body, &products); err != nil {
			return 0, fmt.Errorf("failed to decode product list response: %w", err)
		}

		// Check the count of products
		switch count := *products.Count; count {
		case 1:
			product := (*products.Results)[0]
			utils.DebugPrint("Product %s has id %d", productName, *product.Id)
			return *product.Id, nil
		case 0:
			return 0, fmt.Errorf("no products returned")
		default:
			return 0, fmt.Errorf("more than one product with the same name exists")
		}
	case http.StatusNotFound:
		return 0, fmt.Errorf("product not found")
	default:
		return 0, fmt.Errorf("unexpected status code %d when listing products", apiResp.StatusCode())
	}
}

func ListEngagements(ctx *context.Context, client *dd.ClientWithResponses, productId int) (*dd.PaginatedEngagementList, error) {
	var engagements dd.PaginatedEngagementList

	// List engagements
	resp, err := client.EngagementsListWithResponse(*ctx, &dd.EngagementsListParams{
		Product: &productId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list engagements: %w", err)
	}

	// Check the response status code
	if resp.StatusCode() != http.StatusOK {
		utils.DebugPrint("Error in fetching engagements:", string(resp.Body))
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	// Decode the response body
	err = json.Unmarshal(resp.Body, &engagements)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON response: %w", err)
	}

	return &engagements, nil
}

func CreateEngagement(ctx *context.Context, client *dd.ClientWithResponses, containers []string, productId int) error {
	// Prepare the request body
	requestBody := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(requestBody)
	defer multipartWriter.Close()

	// Add fields to the request body
	for _, container := range containers {
		_ = multipartWriter.WriteField("tags", container)
	}
	_ = multipartWriter.WriteField("product", strconv.Itoa(productId))
	_ = multipartWriter.WriteField("target_start", time.Now().Format("2006-01-02"))
	_ = multipartWriter.WriteField("target_end", time.Now().Format("2006-01-02"))
	_ = multipartWriter.WriteField("name", "Grype_eng")
	_ = multipartWriter.WriteField("deduplication_on_engagement", "true")

	// Create the engagement
	response, err := client.EngagementsCreateWithBodyWithResponse(*ctx, multipartWriter.FormDataContentType(), requestBody)
	if err != nil {
		return fmt.Errorf("error creating engagement API call: %v", err)
	}

	// Check the response status code
	if response.StatusCode() != http.StatusCreated {
		return fmt.Errorf("error: engagement not created. Status code: %d, Response: %s", response.StatusCode(), string(response.Body))
	}

	utils.DebugPrint("Engagement Created")
	return nil
}

func DeleteEngagement(ctx *context.Context, client *dd.ClientWithResponses, engagementID int) error {
	// Delete engagement
	resp, err := client.EngagementsDestroyWithResponse(*ctx, engagementID)
	if err != nil {
		return fmt.Errorf("failed to delete engagement: %w", err)
	}

	// Check response status code
	if resp.StatusCode() != http.StatusNoContent {
		return fmt.Errorf("engagement not deleted: %s", string(resp.Body))
	}

	utils.DebugPrint("Engagement %d deleted", engagementID)
	return nil
}

func ImportGrypeScan(
	ctx *context.Context,
	client *dd.ClientWithResponses,
	namespace, containerName, imageID, podName, fileName string,
) error {
	// Prepare request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	formFields := map[string]string{
		"product_type_name":                      namespace,
		"active":                                 "true",
		"verified":                               "true",
		"close_old_findings":                     "true",
		"test_title":                             containerName,
		"engagement_name":                        "Grype_eng",
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
		"scan_type":                              "Anchore Grype",
	}

	for key, value := range formFields {
		_ = writer.WriteField(key, value)
	}

	// Add file
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return fmt.Errorf("error creating form file: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("error copying file content: %w", err)
	}

	// Close the writer
	if err := writer.Close(); err != nil {
		return fmt.Errorf("error closing multipart writer: %w", err)
	}

	// Import Scan
	apiResp, err := client.ImportScanCreateWithBodyWithResponse(*ctx, writer.FormDataContentType(), body)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}

	// Check the response status code
	switch apiResp.StatusCode() {
	case http.StatusCreated:
		utils.DebugPrint("Scan Imported!")
	default:
		return fmt.Errorf("error in importing scan: %s", string(apiResp.Body))
	}

	return nil
}

func ListSystemSettings(ctx *context.Context, client *dd.ClientWithResponses) (*dd.PaginatedSystemSettingsList, error) {
	var systemSettings dd.PaginatedSystemSettingsList

	// Get system settings
	apiResp, err := client.SystemSettingsListWithResponse(*ctx, &dd.SystemSettingsListParams{})
	if err != nil {
		return nil, fmt.Errorf("error getting system settings: %v", err)
	}

	// Check the response status code
	if apiResp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", apiResp.StatusCode())
	}

	// Decode the response body
	err = json.Unmarshal(apiResp.Body, &systemSettings)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON response: %w", err)
	}

	return &systemSettings, nil
}

func UpdateSystemSettings(ctx *context.Context, client *dd.ClientWithResponses, id int, enableDeduplication bool, deleteDuplicates bool, maxDuplicates int) error {
	// Update system settings
	apiResp, err := client.SystemSettingsUpdateWithResponse(*ctx, id, dd.SystemSettingsUpdateJSONRequestBody{
		EnableDeduplication: &enableDeduplication,
		DeleteDuplicates:    &deleteDuplicates,
		MaxDupes:            &maxDuplicates,
	})
	if err != nil {
		return fmt.Errorf("error updating system settings: %v", err)
	}

	// Check the response status code
	if apiResp.StatusCode() != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", apiResp.StatusCode())
	}
	utils.DebugPrint("System settings for profile %d updated.", id)

	return nil
}
