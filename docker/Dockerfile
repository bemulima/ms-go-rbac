FROM golang:1.25.1-alpine AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ms-rbac-service ./cmd/ms-rbac-service

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /app/ms-rbac-service /app/ms-rbac-service
EXPOSE 8080
ENTRYPOINT ["/app/ms-rbac-service"]
