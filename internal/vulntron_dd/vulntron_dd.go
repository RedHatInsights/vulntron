package vulntron_dd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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
		tokenclient, err := dd.NewClientWithResponses(url)
		if err != nil {
			return nil, fmt.Errorf("error: Error instantiating the client")
		}

		tokenResponse, err := tokenclient.ApiTokenAuthCreateWithResponse(*ctx, dd.ApiTokenAuthCreateJSONRequestBody{
			Username: &username,
			Password: &password,
		})
		if err != nil {
			return nil, fmt.Errorf("error: Error Creating API token %s", err)
		}
		//TODO response handling

		err = json.Unmarshal(tokenResponse.Body, &authToken)
		if err != nil {
			return nil, fmt.Errorf("error: Decoding JSON: %s", err)
		}

		if authToken.Token != nil {
			fmt.Printf("Token: %s\n", *authToken.Token)
		} else {
			return nil, fmt.Errorf("error: Token not present in the response")
		}
	}

	tokenProvider, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", fmt.Sprintf("Token %s", *authToken.Token))
	if err != nil {
		return nil, fmt.Errorf("error: token setup: %s", err.Error())
	}

	client, err := dd.NewClientWithResponses(url, dd.WithRequestEditorFn(tokenProvider.Intercept))
	if err != nil {
		return nil, fmt.Errorf("error: setting up client API: %s", err.Error())
	}

	return client, err

}

func ListProductTypes(ctx *context.Context, client *dd.ClientWithResponses) (*dd.PaginatedProductTypeList, error) {
	apiRespProductType, err := client.ProductTypesListWithResponse(*ctx, &dd.ProductTypesListParams{})
	if err != nil {
		return nil, fmt.Errorf("error: Listing Product Types: %s", err.Error())
	}
	var ProductTypes dd.PaginatedProductTypeList

	if apiRespProductType.StatusCode() == 200 {
		/*
			product_type := apiRespProductType.Body
			res, err := utils.PrettyString(string(product_type))
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(res)
		*/

		// Unmarshal the JSON response into the ProductTypes variable
		err = json.Unmarshal(apiRespProductType.Body, &ProductTypes)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		return &ProductTypes, err
	} else {
		return nil, err
		// TODO correct error return
	}
}

func CreateProductType(ctx *context.Context, client *dd.ClientWithResponses, nameSpace string) (int, error) {
	product_type_desc := "Sample description product type"
	var productTypeResp dd.ProductType

	apiResp, err := client.ProductTypesCreateWithResponse(*ctx, dd.ProductTypesCreateJSONRequestBody{
		Name:            nameSpace,
		Description:     &product_type_desc,
		CriticalProduct: nil,
		KeyProduct:      nil,
	})
	if err != nil {
		return 0, fmt.Errorf(err.Error())
	}

	if apiResp.StatusCode() != 201 {
		return 0, fmt.Errorf("error: Product Type Not created: %s", string(apiResp.Body))
	} else {
		fmt.Println("Product Type Created:", string(apiResp.Body))

		err = json.Unmarshal(apiResp.Body, &productTypeResp)
		if err != nil {
			return 0, fmt.Errorf("error: Decoding JSON: %s", err)
		}

	}

	return *productTypeResp.Id, err
}

func CreateProduct(ctx *context.Context, client *dd.ClientWithResponses, podName string, productTypeId int) (bool, int, error) {
	var ProductResponse dd.Product

	// TODO fix description
	apiResp, err := client.ProductsCreateWithResponse(*ctx, dd.ProductsCreateJSONRequestBody{
		Name:        podName,
		Description: "Sample description product",
		ProdType:    productTypeId,
	})
	if err != nil {
		return false, 0, err
	}

	if apiResp.StatusCode() == 400 {
		// utils.DebugPrint("Product already exists skipping: %s", string(apiResp.Body))
		utils.DebugPrint("Product: %s already exists skipping!", podName)
		return false, 0, nil

	} else if apiResp.StatusCode() == 201 {
		//utils.DebugPrint("Created:", string(apiResp.Body))
		err = json.Unmarshal(apiResp.Body, &ProductResponse)
		if err != nil {
			return false, 0, fmt.Errorf(err.Error())
		}
		utils.DebugPrint("New Product Created with id: %d and name: %s", *ProductResponse.Id, ProductResponse.Name)

		return true, *ProductResponse.Id, nil

	} else {
		fmt.Println("Error:", string(apiResp.Body))
		return false, 0, fmt.Errorf(string(apiResp.Body))
	}
}

func ListProducts(ctx *context.Context, client *dd.ClientWithResponses, podName string) (int, error) {
	var Products dd.PaginatedProductList

	apiRespProducts, err := client.ProductsListWithResponse(*ctx, &dd.ProductsListParams{
		Name: &podName,
	})
	if err != nil {
		return 0, fmt.Errorf(err.Error())
	}

	if apiRespProducts.StatusCode() == 200 {
		err = json.Unmarshal(apiRespProducts.Body, &Products)
		if err != nil {
			return 0, fmt.Errorf(err.Error())
		}

		if *Products.Count == 1 {
			fr := (*Products.Results)[0]
			utils.DebugPrint("Product %s has id %d", podName, *fr.Id)

			return *fr.Id, err

		} else if *Products.Count == 0 {
			return 0, fmt.Errorf("error: This should not happen. (no products returned)")
		} else {
			return 0, fmt.Errorf("error: More than two of the products with same name exists")
		}
	} else {
		return 0, fmt.Errorf("error: Product not found")
	}
}

func ListEngagements(ctx *context.Context, client *dd.ClientWithResponses, productId int) (*dd.PaginatedEngagementList, error) {
	var Engagements dd.PaginatedEngagementList

	resp, err := client.EngagementsListWithResponse(*ctx, &dd.EngagementsListParams{
		Product: &productId,
	})
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	if resp.StatusCode() != 200 {
		utils.DebugPrint("Error in fetching engagements:", string(resp.Body))
		return nil, fmt.Errorf("error: No engagements in current product")

	} else if resp.StatusCode() == 200 {

		err = json.Unmarshal(resp.Body, &Engagements)
		if err != nil {
			return nil, fmt.Errorf("error: Decoding JSON: %s", err)
		}

	}
	return &Engagements, nil
}

func CreateEngagement(
	ctx *context.Context,
	client *dd.ClientWithResponses,
	containers []string,
	productId int,

) error {
	// Create new Engagement inside the Product
	eng_body := &bytes.Buffer{}
	eng_writer := multipart.NewWriter(eng_body)

	for _, container := range containers {
		eng_writer.WriteField("tags", container)
	}

	eng_writer.WriteField("product", strconv.Itoa(productId))
	eng_writer.WriteField("target_start", string(time.Now().Format("2006-01-02")))
	eng_writer.WriteField("target_end", string(time.Now().Format("2006-01-02")))
	eng_writer.WriteField("name", "Grype_eng")
	eng_writer.WriteField("deduplication_on_engagement", "true")

	//eng_writer.WriteField("")

	eng_writer.Close()

	EngCreateApiResp, err := client.EngagementsCreateWithBodyWithResponse(*ctx, eng_writer.FormDataContentType(), eng_body)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	if EngCreateApiResp.StatusCode() != 201 {
		return fmt.Errorf("error: Engagement Not created: %s", string(EngCreateApiResp.Body))
	} else {
		utils.DebugPrint("Engagement Created")
		return nil
	}
}

func DeleteEngagement(ctx *context.Context, client *dd.ClientWithResponses, engagementId int) error {

	EngDeleteApiResp, err := client.EngagementsDestroyWithResponse(*ctx, engagementId)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	if EngDeleteApiResp.StatusCode() != 204 {
		return fmt.Errorf("error: Engagement Not deleted: %s", string(EngDeleteApiResp.Body))
	} else {
		utils.DebugPrint("Engagement %d deleted", engagementId)
		return nil
	}

}

func ImportGrypeScan(
	ctx *context.Context,
	client *dd.ClientWithResponses,
	namespace string,
	containerName string,
	imageId string,
	podName string,
	fileName string,

) error {

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("product_type_name", namespace)
	writer.WriteField("active", "true")
	writer.WriteField("verified", "true")
	writer.WriteField("close_old_findings", "true")
	writer.WriteField("test_title", containerName)
	writer.WriteField("engagement_name", "Grype_eng")
	writer.WriteField("build_id", "")
	writer.WriteField("deduplication_on_engagement", "true")
	writer.WriteField("push_to_jira", "false")
	writer.WriteField("minimum_severity", "Info")
	writer.WriteField("close_old_findings_product_scope", "true")
	writer.WriteField("scan_date", string(time.Now().Format("2006-01-02")))
	writer.WriteField("create_finding_groups_for_all_findings", "false")
	writer.WriteField("engagement_end_date", "")
	writer.WriteField("tags", imageId)
	writer.WriteField("product_name", podName)
	writer.WriteField("auto_create_context", "true")
	writer.WriteField("scan_type", "Anchore Grype")
	//writer.WriteField("engagement", "")

	// Add file
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		panic(err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		panic(err)
	}

	// Close the writer to finish writing the request body
	writer.Close()

	/*
		var buf bytes.Buffer
		err := json.NewEncoder(&buf).Encode(body)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}*/

	apiResp, err := client.ImportScanCreateWithBodyWithResponse(*ctx, writer.FormDataContentType(), body)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if apiResp.StatusCode() != 201 {
		return fmt.Errorf("error: Error in importing scan: %s", string(apiResp.Body))

	} else if apiResp.StatusCode() == 201 {
		//utils.DebugPrint("Scan Imported:", string(apiResp.Body))
		utils.DebugPrint("Scan Imported!")
	}
	return nil
}
