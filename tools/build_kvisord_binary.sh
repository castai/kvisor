#!/bin/bash

set -e

docker run --rm \
  -v $(pwd)/.cache/go-build:/home/app/.cache/go-build \
  -v $(pwd)/.cache/go-mod:/home/app/go/pkg/mod \
  -v $(pwd):/app --privileged -w /app kvisor-builder \
  make kvisord
