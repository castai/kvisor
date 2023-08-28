TARGETARCH ?= amd64

build-agent:
	GOOS=linux GOARCH=$(TARGETARCH) go build -ldflags="-s -w" -o bin/castai-kvisor-$(TARGETARCH) ./cmd/agent

build-agent-github-docker: build-agent
	docker buildx build --build-arg TARGETARCH=$(TARGETARCH) --platform linux/$(TARGETARCH) -t ghcr.io/castai/kvisor/kvisor:$(IMAGE_TAG) -f Dockerfile.agent .

push-agent-github-docker: build-agent-github-docker
	docker push ghcr.io/castai/kvisor/kvisor:$(IMAGE_TAG)

build-imgcollector:
	GOOS=linux GOARCH=$(TARGETARCH) go build -ldflags="-s -w" -o bin/castai-imgcollector-$(TARGETARCH) ./cmd/imgcollector

build-imgcollector-github-docker: build-imgcollector
	docker buildx build --build-arg TARGETARCH=$(TARGETARCH) --platform linux/$(TARGETARCH) -t ghcr.io/castai/kvisor/kvisor-imgcollector:$(IMAGE_TAG) -f Dockerfile.imgcollector .

push-imgcollector-github-docker: build-imgcollector-github-docker
	docker push ghcr.io/castai/kvisor/kvisor-imgcollector:$(IMAGE_TAG)

generate:
	go generate ./...
