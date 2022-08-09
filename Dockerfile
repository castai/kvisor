FROM alpine:3.13
COPY bin/castai-sec-agent /usr/local/bin/castai-sec-agent
CMD ["castai-sec-agent"]
