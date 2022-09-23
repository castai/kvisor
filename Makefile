build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/castai-sec-agent ./cmd/agent

build-gcr-docker: build
	docker build -t us-docker.pkg.dev/castai-hub/library/sec-agent:$(IMAGE_TAG) -f Dockerfile.agent .

build-github-docker: build
	docker build -t ghcr.io/castai/sec-agent:$(IMAGE_TAG) -f Dockerfile.agent .

push-github-docker: build-github-docker
	docker push ghcr.io/castai/sec-agent:$(IMAGE_TAG)

generate:
	go generate ./...
