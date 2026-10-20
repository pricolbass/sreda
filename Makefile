.PHONY: build test check

build:
	go build -trimpath -o bin/sreda ./cmd/sreda
	go build -trimpath -o bin/sreda-agent ./cmd/sreda-agent
	go build -trimpath -o bin/sreda-network ./cmd/sreda-network

test:
	go test -race -timeout 20m ./...

check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"
