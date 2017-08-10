FROM golang:1.8
MAINTAINER Kumbirai Tanekha <kumbirai.tanekha@cyberark.com>

RUN go get -u github.com/jstemmer/go-junit-report
RUN go get github.com/tools/godep
RUN go get github.com/smartystreets/goconvey
RUN apt-get update && apt-get install jq

WORKDIR /go/src/github.com/conjurinc/api-go

COPY . .

ENV GOOS=linux
ENV GOARCH=amd64

EXPOSE 8080

CMD /bin/bash
