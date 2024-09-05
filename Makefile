REPO_ROOT := $(CURDIR)
GOBIN=$(shell pwd)/bin
GOPATH := $(shell go env GOPATH)
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
GOFILES=$(wildcard *.go)
GONAME=dex-k8s-authenticator
IMAGE_NAME ?= mesosphere/dex-k8s-authenticator
DISTROLESS_STATIC_IMAGE ?= gcr.io/distroless/static@sha256:6706c73aae2afaa8201d63cc3dda48753c09bcd6c300762251065c0f7e602b25
TAG ?= latest
export CGO_ENABLED=0
export GO111MODULE ?= on
export GOPRIVATE ?= github.com/mesosphere

KONVOY_ASYNC_AUTH_VERSION ?= v0.2.0

all: build

.PHONY: get
get:
	@go get -d .

.PHONY: konvoy-async-auth
konvoy-async-auth: install-tools
	@rm -rf _build/konvoy-async-auth*
	@gh release download $(KONVOY_ASYNC_AUTH_VERSION) -R https://github.com/mesosphere/konvoy-async-auth -D _build/
	@tar -xjvf "_build/konvoy-async-auth_$(KONVOY_ASYNC_AUTH_VERSION)_linux_amd64.tar.gz" -C html/static/downloads
	@tar -xjvf "_build/konvoy-async-auth_$(KONVOY_ASYNC_AUTH_VERSION)_darwin_amd64.tar.gz" -C html/static/downloads
	@tar -xjvf "_build/konvoy-async-auth_$(KONVOY_ASYNC_AUTH_VERSION)_darwin_arm64.tar.gz" -C html/static/downloads
	@tar -xjvf "_build/konvoy-async-auth_$(KONVOY_ASYNC_AUTH_VERSION)_windows_amd64.tar.gz" -C html/static/downloads

.PHONY: build
build: get konvoy-async-auth install-tools
	@echo "Building $(GOFILES) to ./bin"
	@go build -o bin/$(GOOS)/$(GOARCH)/$(GONAME) $(GOFILES)

test: get install-tools
	@go test ./...

.PHONY: container
# Make sure to build the binary with the correct OS/architecture so it can be run in the container
container: export GOOS=linux
container: export GOARCH=amd64
container: konvoy-async-auth build
	@echo "Building container image"
	docker build --build-arg DISTROLESS_STATIC_IMAGE=$(DISTROLESS_STATIC_IMAGE) -t ${IMAGE_NAME}:${TAG} .

.PHONY: push-image
push-image:
	@echo "Pushing container image: $(IMAGE_NAME):$(TAG)"
	docker push ${IMAGE_NAME}:${TAG}

.PHONY: clean
clean:
	@echo "Cleaning"
	@go clean
	rm -rf ./bin
	rm -rf ./_build

define install_tool
	$(if $(1), \
		asdf plugin list | grep -E '^$(1)$$' &>/dev/null || asdf plugin add $(1), \
		grep -Eo '^[^#]\S+' $(REPO_ROOT)/.tool-versions | xargs -I{} bash -ec 'asdf plugin list | grep -E '^{}$$' &>/dev/null || asdf plugin add {}' \
	)
	asdf install $1
endef

.PHONY: install-tools
install-tools: ## Install all tools
install-tools: $(info $(M) installing all tools)
	$(call install_tool,)

.PHONY: install-tool.%
install-tool.%: ## Install specific tool
install-tool.%: ; $(info $(M) installing $*)
	$(call install_tool,$*)
