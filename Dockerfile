FROM golang:1.10
MAINTAINER Conjur Inc.

RUN go get -u github.com/jstemmer/go-junit-report
RUN go get -u github.com/golang/dep/cmd/dep
RUN go get github.com/smartystreets/goconvey
RUN apt-get update && apt-get install -y jq less vim

WORKDIR /go/src/github.com/cyberark/conjur-api-go

COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure --vendor-only

COPY . .

ENV GOOS=linux
ENV GOARCH=amd64

EXPOSE 8080

CMD /bin/bash
