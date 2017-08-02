FROM golang:1.8

WORKDIR /go/src/github.com/conjurinc/api-go

COPY . .

ENV GOOS=linux
ENV GOARCH=amd64

ENTRYPOINT ["/bin/bash"]