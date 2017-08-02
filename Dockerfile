FROM golang:1.8

RUN go get -u github.com/jstemmer/go-junit-report
RUN go get github.com/tools/godep
RUN go get github.com/smartystreets/goconvey

WORKDIR /go/src/github.com/conjurinc/api-go

COPY . .

ENV GOOS=linux
ENV GOARCH=amd64

ENTRYPOINT ["/bin/bash"]
