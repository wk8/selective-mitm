.DEFAULT_GOAL := all

.PHONY: all
all: test lint

# the TEST_FLAGS env var can be set to eg run only specific tests
# the coverage output can be open with `go tool cover -html=coverage.out`
.PHONY: test
test:
	go test ./... -v -count=1 -race -cover -coverprofile=coverage.out "$$TEST_FLAGS"

.PHONY: lint
lint:
	golangci-lint run
