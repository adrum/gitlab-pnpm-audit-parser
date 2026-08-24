# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY main.go ./

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/gitlab-pnpm-audit-parser .

FROM scratch

COPY --from=builder /out/gitlab-pnpm-audit-parser /usr/local/bin/gitlab-pnpm-audit-parser

WORKDIR /src

ENTRYPOINT ["/usr/local/bin/gitlab-pnpm-audit-parser"]
CMD ["--help"]
