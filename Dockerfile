#FROM registry.access.redhat.com/ubi8/go-toolset:1.20.10
FROM golang:alpine AS builder

USER root

#RUN dnf install -y libpq curl 

COPY . /app

WORKDIR /app

RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o main .


# CMD ["/app/main", "-type", "auto", "-config", "config.yaml", "quay.io/cloudservices/rbac"]
# CMD ["/app/main", "--type", "auto", "--config", "config.yaml"]
# CMD ["/bin/sh", "-c", "/app/main -type auto quay.io/cloudservices/rbac && tail -f /dev/null"]

FROM alpine
# Copy our static executable.
COPY --from=builder /app /app
# Run the vulntron binary.
#ENTRYPOINT ["/go/bin/hello"]
CMD ["/app/main", "--type", "auto", "--config", "/app/config.yaml"]