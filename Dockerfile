# syntax=docker/dockerfile:1.7

FROM golang:1.27.3-bookworm AS build
ARG SERVICE
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/custody-service \
    "./cmd/${SERVICE}"
RUN mkdir -p /out/keys /out/jwks

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/custody-service /custody-service
COPY --from=build --chown=65532:65532 /out/keys /var/lib/custody/keys
COPY --from=build --chown=65532:65532 /out/jwks /var/lib/custody/jwks
USER 65532:65532
ENTRYPOINT ["/custody-service"]
