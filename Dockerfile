FROM alpine:3.18.5

# Needed for kube-bench.
RUN apk --no-cache add procps

ARG TARGETARCH
COPY ./bin/castai-kvisor-$TARGETARCH /usr/local/bin/castai-kvisor
COPY ./cmd/kvisor/kubebench/kubebench-rules /etc/kubebench-rules
ENTRYPOINT ["/usr/local/bin/castai-kvisor"]
