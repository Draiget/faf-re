# Build from tools/:  docker build -f deploy/Dockerfile -t <registry>/mpemu-server:<tag> .
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/mpemu-server ./cmd/mpemu-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mpemu-server /mpemu-server
# MPEMU_SECRET comes from the orchestrator (Vault / secrets-store CSI), never the image.
ENTRYPOINT ["/mpemu-server", "-http", "0.0.0.0:8080", "-logs", "/tmp/mpemu-logs"]
