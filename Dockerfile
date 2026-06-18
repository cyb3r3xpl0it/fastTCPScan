# --- etapa de compilación ---
FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /fastTCPScan .

# --- imagen final ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates
COPY --from=build /fastTCPScan /usr/local/bin/fastTCPScan

ENTRYPOINT ["fastTCPScan"]
