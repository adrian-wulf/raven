# Multi-stage build for minimal image
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git tree-sitter-dev build-base

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-w -s" -o raven .

# Final minimal image
FROM alpine:3.19

LABEL org.opencontainers.image.title="Raven Security Scanner"
LABEL org.opencontainers.image.description="AI-native SAST scanner with 1900+ rules, 10 LLM providers, 7-layer FP reduction"
LABEL org.opencontainers.image.source="https://github.com/raven-security/raven"
LABEL org.opencontainers.image.version="2.5.0"

RUN apk add --no-cache ca-certificates git

COPY --from=builder /build/raven /usr/local/bin/raven
COPY --from=builder /build/rules /opt/raven/rules

ENV RAVEN_RULES_PATH=/opt/raven/rules
ENV PATH="/usr/local/bin:${PATH}"

# Create non-root user for scanning
RUN adduser -D -u 1000 scanner && mkdir -p /workspace
USER scanner
WORKDIR /workspace

ENTRYPOINT ["raven"]
CMD ["scan"]
