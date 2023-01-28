FROM golang:latest

RUN apt-get update \
    && apt-get install -y \
        postgresql-client \
        curl \
        syft \
        grype

COPY . /app

WORKDIR /app

RUN go build -o main .

CMD ["/app/main"]