ARG FROM_IMAGE="golang:1.25"
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

# gocovmerge is an old tool with no go.mod, so `go install ...@latest` resolves
# its golang.org/x/tools/cover import to the latest x/tools (v0.50.0), which now
# requires Go >= 1.26 and fails on this Go 1.25 image. The toolchain cannot be
# auto-upgraded here because GOFIPS140 pins it. Instead, build gocovmerge inside
# a throwaway module with x/tools pinned to v0.49.0 (the last release that
# supports Go 1.25), installing the package WITHOUT the @version suffix so the
# pin is honored. The Go version tests run under is unchanged.
RUN mkdir /tmp/gocovmerge-build && cd /tmp/gocovmerge-build && \
    go mod init gocovmerge-build && \
    go get golang.org/x/tools@v0.49.0 && \
    go get github.com/wadey/gocovmerge@latest && \
    go install github.com/wadey/gocovmerge && \
    cd / && rm -rf /tmp/gocovmerge-build

WORKDIR /conjur-api-go

COPY go.mod go.sum ./
RUN go mod download

COPY . .
