BINARY  := fastTCPScan
PREFIX  ?= /usr/local/bin
LDFLAGS := -s -w

.PHONY: all build compress install uninstall test vet fmt clean

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

## vet: análisis estático
vet:
	go vet ./...

## fmt: formatea el código
fmt:
	gofmt -w .

## clean: elimina el binario local
clean:
	rm -f $(BINARY)
