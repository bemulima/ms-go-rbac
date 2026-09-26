ARG TARGETOS=linux
ARG TARGETARCH=amd64

FROM --platform=$BUILDPLATFORM golang:1.25.1-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o ms-rbac-service ./cmd/ms-rbac-service \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o ms-rbac-migrate ./cmd/ms-rbac-migrate

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=builder /app/ms-rbac-service /app/ms-rbac-service
COPY --from=builder /app/ms-rbac-migrate /app/ms-rbac-migrate
COPY --from=builder /app/migrations /app/migrations
EXPOSE 8080
ENTRYPOINT ["/app/ms-rbac-service"]
