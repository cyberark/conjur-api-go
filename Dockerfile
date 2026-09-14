ARG FROM_IMAGE="golang:1.26"
FROM ${FROM_IMAGE}
LABEL maintainer="Palo Alto Networks Idira™"

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
                       libc-dev && \
    # Pick up the Debian security fixes for the perl packages the base golang
    # image ships unpatched (perl 5.40.1-6+deb13u1): CVE-2026-8376,
    # CVE-2026-13221, CVE-2026-42496. --only-upgrade so nothing new is pulled in.
    apt-get install -y --only-upgrade \
                       perl-base \
                       perl \
                       libperl5.40 && \
    rm -rf /var/lib/apt/lists/*

RUN go install github.com/jstemmer/go-junit-report@latest && \
    go install github.com/afunix/gocov/gocov@latest && \
    go install github.com/AlekSi/gocov-xml@latest

RUN go install github.com/wadey/gocovmerge@latest

WORKDIR /conjur-api-go

COPY go.mod go.sum ./
RUN go mod download

COPY . .
