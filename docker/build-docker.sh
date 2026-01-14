#!/bin/bash

# Build Open-TEE Docker image
# Uses Ubuntu 25.04 with CMake build system

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build -f "$SCRIPT_DIR/Dockerfile.opentee" "$SCRIPT_DIR" -t opentee:latest

echo ""
echo "✓ Docker image 'opentee:latest' built successfully"
echo ""
echo "Run with: ./run-docker.sh"
