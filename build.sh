#!/bin/bash
# build.sh

set -e

BUILD_TYPE=${1:-Release}
BUILD_DIR="build-${BUILD_TYPE,,}"

echo "Building supacrypt-pkcs11 in ${BUILD_TYPE} mode..."

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Configure
cmake .. \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DBUILD_TESTING=ON \
    -DBUILD_EXAMPLES=ON \
    -DENABLE_COVERAGE=$([ "${BUILD_TYPE}" = "Debug" ] && echo "ON" || echo "OFF")

# Build
cmake --build . --parallel $(nproc)

# Run tests
ctest --output-on-failure

echo "Build complete!"