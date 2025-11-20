# Generate api contracts from protobuf.
.PHONY: gen-proto
gen-proto:
	protoc api/v1/runtime/common.proto --go_out=paths=source_relative:.
	protoc api/v1/runtime/runtime_agent_api.proto --go_out=paths=source_relative:. --go-grpc_out=require_unimplemented_servers=false:. --go-grpc_opt=paths=source_relative
	protoc api/v1/kube/kube_api.proto --go_out=paths=source_relative:. --go-grpc_out=require_unimplemented_servers=false:. --go-grpc_opt=paths=source_relative

UNAME_M ?= $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
   ARCH = x86_64
   LINUX_ARCH = x86
   GO_ARCH = amd64
endif

ifeq ($(UNAME_M),aarch64)
   ARCH = arm64
   LINUX_ARCH = arm64
   GO_ARCH = arm64
endif

ifeq ($(UNAME_M),arm64)
   ARCH = arm64
   LINUX_ARCH = arm64
   GO_ARCH = arm64
endif

LAST_GIT_TAG ?= $(shell $(CMD_GIT) describe --tags --match 'v*' 2>/dev/null)
VERSION ?= $(if $(RELEASE_TAG),$(RELEASE_TAG),$(LAST_GIT_TAG))
ifeq ($(VERSION),)
    VERSION = local-$(shell date +%s)
endif

CMD_TR ?= tr
CMD_CUT ?= cut
CMD_CP ?= cp
CMD_AWK ?= awk
CMD_SED ?= sed
CMD_GIT ?= git
CMD_CLANG ?= clang
CMD_LLC ?= llc
CMD_STRIP ?= llvm-strip
CMD_RM ?= rm
CMD_INSTALL ?= install
CMD_MKDIR ?= mkdir
CMD_TOUCH ?= touch
CMD_PKGCONFIG ?= pkg-config
BPF_VCPU ?= v2
CMD_GO ?= go

KVISOR_EBPF_OBJ_CORE_HEADERS = $(shell find cmd/agent/ebpf/c -name *.h)
KVISOR_EBPF_OBJ_SRC = ./cmd/agent/ebpf/c/tracee.bpf.c

OUTPUT_DIR_BPF = ./dist
OUTPUT_DIR_BIN = ./bin

$(OUTPUT_DIR_BIN):
	@$(CMD_MKDIR) -p $@

$(OUTPUT_DIR_BPF):
	@$(CMD_MKDIR) -p $@

STATIC ?= 1
GO_TAGS_EBPF = core,ebpf
CGO_EXT_LDFLAGS_EBPF =

ifeq ($(STATIC), 1)
    CGO_EXT_LDFLAGS_EBPF += -static
    GO_TAGS_EBPF := $(GO_TAGS_EBPF),netgo
endif

.PHONY: builder-image
builder-image: $(OUTPUT_DIR_BPF)/builder-image.txt


$(OUTPUT_DIR_BPF)/builder-image.txt: $(OUTPUT_DIR_BPF)
	echo $(GO_ARCH)
	docker build -t ghcr.io/castai/kvisor/kvisor-builder:latest --build-arg TARGETARCH=$(GO_ARCH) . -f Dockerfile.builder
	touch $(OUTPUT_DIR_BPF)/builder-image.txt

CMD_DOCKER_BUILDER=docker run --rm \
	-v $$(pwd)/.cache/go-build:/home/.cache/go-build \
	-v $$(pwd)/.cache/go-mod:/home/go/pkg/mod \
	-v $$(pwd):/app \
	-w /app ghcr.io/castai/kvisor/kvisor-builder:latest

CMD_DOCKER_BUILDER_LOCAL=docker run --rm -it --privileged --cap-add SYS_ADMIN --pid host --net host --name kvisor-builder \
	-v $$(pwd)/.cache/go-build:/home/.cache/go-build \
	-v $$(pwd)/.cache/go-mod:/home/go/pkg/mod \
	-v $$(pwd):/app \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-w /app ghcr.io/castai/kvisor/kvisor-builder:latest

.PHONY: gen-args-types
gen-args-types:
	go generate ./pkg/ebpftracer/decoder

.PHONY: gen-bpf
gen-bpf:
	go generate ./pkg/ebpftracer
	go generate ./pkg/ebpftracer/debug

.PHONY: gen-bpf-docker
gen-bpf-docker: builder-image
	$(CMD_DOCKER_BUILDER) make gen-bpf

GO_ENV_EBPF =
GO_ENV_EBPF += GOOS=linux
GO_ENV_EBPF += CC=$(CMD_CLANG)
GO_ENV_EBPF += GOARCH=$(GO_ARCH)
GO_ENV_EBPF += CGO_ENABLED=0
GO_DEBUG_FLAG = -s -w

# Build kvisor binary and docker image.
.PHONY: git-config
git-config:
	git config --global --add safe.directory /app

.PHONY: kvisor-agent
kvisor-agent: $(OUTPUT_DIR_BIN)/kvisor-agent-$(GO_ARCH)

$(OUTPUT_DIR_BIN)/kvisor-agent-$(GO_ARCH): \
#
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.Version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/agent/daemon/

.PHONY: clean-kvisor-agent
clean-kvisor-agent:
#
	$(CMD_RM) -rf $(OUTPUT_DIR_BIN)/kvisor-agent-$(GO_ARCH)

.PHONY: kvisor-image-scanner
kvisor-image-scanner: $(OUTPUT_DIR_BIN)/kvisor-image-scanner-$(GO_ARCH)

$(OUTPUT_DIR_BIN)/kvisor-image-scanner-$(GO_ARCH): \
#
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.Version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/imagescan/

.PHONY: clean-kvisor-image-scanner
clean-kvisor-image-scanner:
#
	$(CMD_RM) -rf $(OUTPUT_DIR_BIN)/kvisor-image-scanner-$(GO_ARCH)

.PHONY: kvisor-linter
kvisor-linter: $(OUTPUT_DIR_BIN)/kvisor-linter-$(GO_ARCH)

$(OUTPUT_DIR_BIN)/kvisor-linter-$(GO_ARCH): \
#
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="$(GO_DEBUG_FLAG) \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.Version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/linter/

.PHONY: clean-kvisor-linter
clean-kvisor-linter:
#
	$(CMD_RM) -rf $(OUTPUT_DIR_BIN)/kvisor-linter-$(GO_ARCH)

# Node collector build
.PHONY: kvisor-node-collector
kvisor-node-collector: $(OUTPUT_DIR_BIN)/kvisor-node-collector-$(GO_ARCH)

$(OUTPUT_DIR_BIN)/kvisor-node-collector-$(GO_ARCH): \
#
	$(CMD_GO) build -v -o $@ ./cmd/collector/

.PHONY: clean-kvisor-node-collector
clean-kvisor-node-collector:
#
	$(CMD_RM) -rf $(OUTPUT_DIR_BIN)/kvisor-node-collector-$(GO_ARCH)


GO_ENV_SERVER =
GO_ENV_SERVER += GOOS=linux
GO_ENV_SERVER += GOARCH=$(GO_ARCH)
GO_ENV_SERVER += CGO_ENABLED=0

IMAGE_TAG ?= local
IMAGE_REPO ?= ghcr.io/castai/kvisor/kvisor

# Agent build.
.PHONY: kvisor-agent-docker
kvisor-agent-docker:
	make kvisor-agent

.PHONY: kvisor-agent-docker-image
kvisor-agent-docker-image: clean-kvisor-agent kvisor-agent-docker
	docker build -t $(IMAGE_REPO)-agent:$(IMAGE_TAG) . -f Dockerfile.agent

.PHONY: kvisor-agent-push-deploy
kvisor-agent-push-deploy: kvisor-agent-docker-image
	docker push $(IMAGE_REPO)-agent:$(IMAGE_TAG)

# Controller build.
.PHONY: clean-kvisor-controller
clean-kvisor-controller:
	$(CMD_RM) -rf $(OUTPUT_DIR_BIN)/kvisor-controller-$(GO_ARCH)

.PHONY: kvisor-controller
kvisor-controller: $(OUTPUT_DIR_BIN)/kvisor-controller-$(GO_ARCH)

$(OUTPUT_DIR_BIN)/kvisor-controller-$(GO_ARCH):
	$(GO_ENV_SERVER) $(CMD_GO) build \
		-ldflags="$(GO_DEBUG_FLAG) \
			-X main.Version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/controller

.PHONY: kvisor-controller-docker-image
kvisor-controller-docker-image: clean-kvisor-controller kvisor-controller
	docker build -t $(IMAGE_REPO)-controller:$(IMAGE_TAG) . -f Dockerfile.controller

.PHONY: kvisor-controller-push-deploy
kvisor-controller-push-deploy: kvisor-controller-docker-image
	docker push $(IMAGE_REPO)-controller:$(IMAGE_TAG)

# Scanners build.
.PHONY: kvisor-scanners-docker
kvisor-scanners-docker:
	make kvisor-agent

.PHONY: kvisor-scanners-docker-image
kvisor-scanners-docker-image: clean-kvisor-image-scanner kvisor-image-scanner clean-kvisor-linter kvisor-linter
	docker build -t $(IMAGE_REPO)-scanners:$(IMAGE_TAG) . -f Dockerfile.scanners

.PHONY: kvisor-scanners-push-deploy
kvisor-scanners-push-deploy: kvisor-scanners-docker-image
	docker push $(IMAGE_REPO)-scanners:$(IMAGE_TAG)

# Event generator build.
.PHONY: clean-kvisor-event-generator
clean-kvisor-event-generator:
	$(CMD_RM) -rf $(OUTPUT_DIR_BIN)/kvisor-event-generator

.PHONY: kvisor-event-generator
kvisor-event-generator: $(OUTPUT_DIR_BIN)/kvisor-event-generator

$(OUTPUT_DIR_BIN)/kvisor-event-generator:
	$(GO_ENV_SERVER) $(CMD_GO) build \
		-ldflags="$(GO_DEBUG_FLAG) \
			-X main.Version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		./cmd/event-generator

.PHONY: kvisor-event-generator-docker-image
kvisor-event-generator-docker-image: clean-kvisor-event-generator kvisor-event-generator
	docker build -t $(IMAGE_REPO)-event-generator:$(IMAGE_TAG) . -f Dockerfile.event-generator

.PHONY: kvisor-event-generator-push-deploy
kvisor-event-generator-push-deploy: kvisor-event-generator-docker-image
	docker push $(IMAGE_REPO)-event-generator:$(IMAGE_TAG)


.PHONY: builder-image-enter
builder-image-enter: builder-image
	$(CMD_DOCKER_BUILDER_LOCAL)

test:
	go test `go list ./... | grep -v /e2e` -short ./...
