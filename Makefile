BINARY  := fastTCPScan
PREFIX  ?= /usr/local/bin
LDFLAGS := -s -w

.PHONY: all build compress install uninstall test cover fuzz vet lint fmt clean

all: build

## build: compila el binario optimizado
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## compress: comprime el binario con UPX (requiere upx)
compress: build
	upx --brute $(BINARY)

## install: compila, comprime e instala en $(PREFIX)
install: compress
	sudo mv $(BINARY) $(PREFIX)/

## uninstall: elimina el binario instalado
uninstall:
	sudo rm -f $(PREFIX)/$(BINARY)

## test: ejecuta los tests unitarios
test:
	go test -v ./...

## cover: tests con cobertura (genera coverage.out)
cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## fuzz: ejecuta los fuzz tests de los parsers (FUZZTIME por defecto 30s)
FUZZTIME ?= 30s
fuzz:
	go test -run=^$$ -fuzz=FuzzExpandPorts -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzExpandCIDR -fuzztime=$(FUZZTIME) .

## vet: análisis estático
vet:
	go vet ./...

## lint: golangci-lint (requiere golangci-lint instalado)
lint:
	golangci-lint run

## fmt: formatea el código
fmt:
	gofmt -w .

## clean: elimina el binario local
clean:
	rm -f $(BINARY)
