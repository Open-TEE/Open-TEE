#!/bin/bash

# Run Open-TEE Docker development environment
#
# The container mounts the source directory and provides a build environment.
# Build artifacts are stored in the mounted source tree.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Create storage directory for TEE secure storage
mkdir -p ~/.TEE_secure_storage

docker run -it --rm \
       --net=host \
       --ipc=host \
       --user "$(id -u):$(id -g)" \
       -v /tmp:/tmp \
       -v ~/.TEE_secure_storage:/home/docker/.TEE_secure_storage \
       -v "$PROJECT_ROOT":/home/docker/opentee \
       -w /home/docker/opentee \
       -e "HOME=/home/docker" \
       opentee:latest
