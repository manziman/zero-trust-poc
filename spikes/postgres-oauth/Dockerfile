# syntax=docker/dockerfile:1.7

FROM golang:1.26.0-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY spikes/postgres-oauth/main.go ./spikes/postgres-oauth/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" \
    -o /out/oauth-smoke ./spikes/postgres-oauth

FROM scratch
COPY --from=build /out/oauth-smoke /oauth-smoke
USER 65532:65532
ENTRYPOINT ["/oauth-smoke"]
