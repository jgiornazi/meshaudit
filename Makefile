VERSION ?= dev
BINARY  := meshaudit
LDFLAGS := -ldflags "-X github.com/jgiornazi/meshaudit/cmd.Version=$(VERSION)"

.PHONY: build test lint clean release

build:
	go build $(LDFLAGS) -o $(BINARY) .

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)

release:
	goreleaser release --clean
