# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o raven ./cmd/raven

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates git

COPY --from=builder /build/raven /usr/local/bin/raven
COPY --from=builder /build/rules /usr/share/raven/rules

ENTRYPOINT ["raven"]
CMD ["scan"]
