fmt:
	go fmt ./...

vet:
	go vet ./...

build: fmt vet
	go build -o bin/vulntron main.go

run: fmt vet
	go run ./main.go --config config.yaml
	
clean:
	go clean 
	rm Vulntron
	rm bin/vulntron

build-clean-db: 
	go build -o bin/clean_dd_db scripts/clean_dd_db.go
