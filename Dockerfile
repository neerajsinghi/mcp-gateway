# syntax=docker/dockerfile:1

FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/mcp-gateway ./cmd/mcp-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-gateway /mcp-gateway
COPY examples/mcp-gateway.yaml /etc/mcp-gateway/mcp-gateway.yaml
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/mcp-gateway"]
CMD ["-config", "/etc/mcp-gateway/mcp-gateway.yaml"]
