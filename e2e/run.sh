#!/bin/bash

set -e

ct install --config ./ct.yaml --all --helm-extra-args "--set image.repository=ghcr.io/castai/kvisor/kvisor --set image.tag=${IMAGE_TAG}"
