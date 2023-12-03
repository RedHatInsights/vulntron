#FROM registry.access.redhat.com/ubi8/go-toolset:1.20.10
FROM golang:latest

USER root

#RUN dnf install -y libpq curl 

COPY . /app

WORKDIR /app

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o main .

CMD ["/app/main", "-type", "auto", "-config", "config.yaml", "quay.io/cloudservices/rbac"]
# CMD ["/bin/sh", "-c", "/app/main -type auto quay.io/cloudservices/rbac && tail -f /dev/null"]