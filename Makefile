GOBIN=$(shell pwd)/bin
GOPATH := $(shell go env GOPATH)
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GOFILES=$(wildcard *.go)
GONAME=dex-k8s-authenticator
IMAGE_NAME=mesosphere/dex-k8s-authenticator
TAG=latest

export GO111MODULE ?= on
export GOPRIVATE ?= github.com/mesosphere

KONVOY_ASYNC_AUTH_VERSION ?= v0.1.3

all: build

get:
	@go get -d .

konvoy-async-auth:
	@rm -rf _build/konvoy-async-auth*
	@gh release download $(KONVOY_ASYNC_AUTH_VERSION) -R https://github.com/mesosphere/konvoy-async-auth -D _build/
	@mkdir -p html/static/downloads/linux html/static/downloads/windows html/static/downloads/darwin
	@tar -xjvf "_build/konvoy-async-auth_$(KONVOY_ASYNC_AUTH_VERSION)_linux.tar.bz2" -C html/static/downloads/linux
	@tar -xjvf "_build/konvoy-async-auth_$(KONVOY_ASYNC_AUTH_VERSION)_darwin.tar.bz2" -C html/static/downloads/darwin
	@tar -xjvf "_build/konvoy-async-auth_$(KONVOY_ASYNC_AUTH_VERSION)_windows.tar.bz2" -C html/static/downloads/windows

build: get
	@echo "Building $(GOFILES) to ./bin"
	@go build -o bin/$(GOOS)/$(GOARCH)/$(GONAME) $(GOFILES)

test: get
	@go test ./...

container: export GOOS=linux
container: export GOARCH=amd64
container: konvoy-async-auth build
	@echo "Building container image"
	docker build -t ${IMAGE_NAME}:${TAG} .

clean:
	@echo "Cleaning"
	@go clean
	rm -rf ./bin
	rm -rf ./_build

.PHONY: build get clean container
