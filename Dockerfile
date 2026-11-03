# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/nexus-gh-auth ./cmd/nexus-gh-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nexus-gh-auth /nexus-gh-auth
EXPOSE 8081 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/nexus-gh-auth", "healthcheck"]
ENTRYPOINT ["/nexus-gh-auth"]
