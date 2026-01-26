# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy everything including vendor directory
COPY . .

# Build the application using vendored dependencies
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o schat .

# Final stage
FROM alpine:latest

WORKDIR /root/

# Copy ca-certificates from builder stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from builder
COPY --from=builder /app/schat .

# Expose SSH port
EXPOSE 2222

# Run the application
CMD ["./schat"]
