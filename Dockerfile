FROM golang:latest

RUN apt-get update \
    && apt-get install -y \
        postgresql-client \
        syft \
        grype

COPY . /app

WORKDIR /app

RUN go build -o main .

CMD ["/app/main"]