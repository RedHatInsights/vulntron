fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

build: fmt vet
	go build -o bin/vulntron main.go

run: fmt vet
	go run ./main.go
	
rundemo: fmt vet
	go run ./main.go quay.io/cloudservices/rbac

runsingledemo: fmt vet
	go run ./main.go --type single --config config.yaml --imagename tomcat --timestamp "Sun, 30 Nov 2023 15:32:07 +0100" --component "tc_demo"

runautodemo: fmt vet
	go run ./main.go --type auto --config config.yaml

clean:
	go clean 
	rm Vulntron