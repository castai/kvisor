build:
	GOOS=linux go build -ldflags="-s -w" -o bin/castai-sec-agent .
	docker build -t us-docker.pkg.dev/castai-hub/library/sec-agent:$(VERSION) .

generate:
	go generate ./...

push:
	docker push us-docker.pkg.dev/castai-hub/library/sec-agent:$(VERSION)

deploy:
	cat deployment.yaml | envsubst | kubectl apply -f -

SHELL := /bin/bash
run:
	source ./.env && go run .

test:
	go test ./... -race

release: build push