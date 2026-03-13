ARG FROM_IMAGE="golang:1.25"
FROM ${FROM_IMAGE}
LABEL maintainer="CyberArk Software Ltd."

ENV GOFIPS140=latest

CMD ["/bin/bash"]
EXPOSE 8080

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
                       bash \
                       gcc \
                       git \
                       jq \
                       less \
                       libc-dev

RUN go install github.com/jstemmer/go-junit-report@latest && \
    go install github.com/afunix/gocov/gocov@latest && \
    go install github.com/AlekSi/gocov-xml@latest

# gocovmerge now requires Go 1.25 - since we only merge 1.25.x coverage anyway we can skip installation to avoid build errors
RUN if go version | grep -q "go1.25"; then \
        go install github.com/wadey/gocovmerge@latest ; \
    fi

WORKDIR /conjur-api-go

COPY go.mod go.sum ./
RUN go mod download

COPY . .
