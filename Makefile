.PHONY: build test check

build:
	go build -trimpath -o bin/sreda ./cmd/sreda

test:
	go test -race ./...

check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"
