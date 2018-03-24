#!/bin/make

GOPATH:=$(shell go env GOPATH)
SOURCES:=$(shell find . -name '*.go')

.PHONY: all deps update fmt test check

all: test

clean:
	go clean

deps:
	go get -v .

update:
	go get -u .

fmt:
	go fmt ./...
	$(GOPATH)/bin/goimports -w -l .

test:
	$(GOPATH)/bin/goimports -w -l .
	go test ./...

check:
	@if [ ! -f $(GOPATH)/bin/gometalinter ]; then go get github.com/alecthomas/gometalinter; fi
	$(GOPATH)/bin/gometalinter ./...

