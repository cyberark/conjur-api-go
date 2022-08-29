ARG FROM_IMAGE="golang:1.17"
FROM ${FROM_IMAGE}
MAINTAINER Conjur Inc.

CMD /bin/bash
EXPOSE 8080

RUN apt update -y && \
    apt install -y bash \
                   gcc \
                   git \
                   jq \
                   less \
                   libc-dev

RUN go install github.com/jstemmer/go-junit-report@latest && \
    go install github.com/axw/gocov/gocov@latest && \
    go install github.com/AlekSi/gocov-xml@latest

WORKDIR /conjur-api-go

COPY go.mod go.sum ./
RUN go mod download

COPY . .
