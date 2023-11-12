FROM registry.access.redhat.com/ubi8/go-toolset:1.18.9-4

USER root
RUN dnf install -y libpq curl 

COPY . /app

WORKDIR /app

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o main .

CMD ["/app/main"]