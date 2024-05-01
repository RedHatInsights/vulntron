# Setup the build image and build the Vulntron application

#FROM registry.access.redhat.com/ubi8/go-toolset:1.20.10
FROM golang:alpine AS builder

USER root

RUN apk --no-cache add ca-certificates git && \
    apk --no-cache add --virtual build-dependencies curl

COPY . /app
WORKDIR /app

RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o bin/vulntron .
RUN go build -o bin/clean_dd_db scripts/clean_dd_db.go


# Setup the deploy image 
FROM alpine

# Install Trivy
RUN apk --no-cache add curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN apk --no-cache add ca-certificates

COPY --from=builder /app /app

# Run the vulntron binary 
CMD /app/bin/vulntron --config /app/config.yaml && watch -n 7200 /app/bin/vulntron --config /app/config.yaml