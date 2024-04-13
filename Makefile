fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

build: fmt vet
	go build -o bin/vulntron main.go

run: fmt vet
	go run ./main.go
	
runautodemo: fmt vet
	go run ./main.go --config config.yaml

clean:
	go clean 
	rm Vulntron