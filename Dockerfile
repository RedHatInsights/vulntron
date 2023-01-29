FROM registry.access.redhat.com/ubi8/go-toolset:1.18.9-4

USER root
RUN dnf install -y libpq curl 

COPY . /app

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o main .

CMD ["/app/main"]