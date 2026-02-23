# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy dependency files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /server ./cmd/server

# Production stage
FROM gcr.io/distroless/static-debian12

# Copy binary and certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /server /server

# Non-root user (distroless uses nonroot by default)
USER nonroot:nonroot

EXPOSE 8081

ENTRYPOINT ["/server"]
