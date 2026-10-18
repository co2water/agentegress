# For MCP directories (Glama and similar) that build a server in a Linux
# sandbox and call tools/list to inspect its tools. Live scanning needs
# Windows, so the container serves the synthetic example machine instead.
# It is not a way to run agentegress on Linux.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /agentegress ./cmd/agentegress

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /agentegress /agentegress
COPY examples/clean.json /examples/clean.json
ENTRYPOINT ["/agentegress", "mcp", "-fixture", "/examples/clean.json"]
