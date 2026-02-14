# syntax=docker/dockerfile:1

FROM docker.io/library/golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/storas ./cmd/storas

FROM docker.io/library/alpine:3.22
RUN addgroup -S storas && adduser -S -G storas storas && apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=build /out/storas /usr/local/bin/storas

VOLUME ["/etc/storas", "/var/lib/storas/data"]
EXPOSE 9000
USER storas

ENTRYPOINT ["/usr/local/bin/storas"]
CMD ["-config", "/etc/storas/config.yaml"]
