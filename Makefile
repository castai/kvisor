build-agent:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/castai-sec-agent ./cmd/agent

build-agent-github-docker: build-agent
	docker build -t ghcr.io/castai/sec-agent:$(IMAGE_TAG) -f Dockerfile.agent .

push-agent-github-docker: build-agent-github-docker
	docker push ghcr.io/castai/sec-agent:$(IMAGE_TAG)

build-imgcollector:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/castai-imgcollector ./cmd/imgcollector

build-imgcollector-github-docker: build-imgcollector
	docker build -t ghcr.io/castai/sec-agent-imgcollector:$(IMAGE_TAG) -f Dockerfile.imgcollector .

push-imgcollector-github-docker: build-imgcollector-github-docker
	docker push ghcr.io/castai/sec-agent-imgcollector:$(IMAGE_TAG)

generate:
	go generate ./...
