FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY cmd/agent ./cmd/agent
WORKDIR /app/cmd/agent

RUN go build -o endpoint-agent main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/cmd/agent/endpoint-agent .

ENV AGENT_CONFIG='{"server_url":"http://api:8000","interval":5}'

CMD ["./endpoint-agent"]
