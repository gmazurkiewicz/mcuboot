#!/bin/bash

# Build script for ClusterFuzzLite deployment
# This builds the MCUboot fuzz targets and prepares them for ClusterFuzzLite

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(dirname "$SCRIPT_DIR")/.."
FUZZ_DIR="$WORKSPACE_DIR/fuzz"

echo "========================================"
echo "Building MCUboot Fuzz Targets for ClusterFuzzLite"
echo "========================================"

# Ensure submodules are initialized
if [ ! -d "$WORKSPACE_DIR/ext/mbedtls-3.6.0" ]; then
    echo "Initializing git submodules..."
    cd "$WORKSPACE_DIR"
    git submodule update --init --recursive
    cd "$SCRIPT_DIR"
fi

# Build using the existing build script
cd "$FUZZ_DIR"
echo "Running existing build.sh..."
./build.sh

# Verify build
if [ ! -f "$FUZZ_DIR/build/fuzz_test" ]; then
    echo "ERROR: fuzz_test binary not found after build!"
    exit 1
fi

echo "Build successful!"
echo "fuzz_test binary: $FUZZ_DIR/build/fuzz_test"

# Test the binary
cd "$FUZZ_DIR"
echo "Running quick smoke test..."
./build/fuzz_test --gtest_list_tests 2>&1 | grep -q "McuBootSuite" && echo "Smoke test passed!" || echo "WARNING: Smoke test may have failed"

# Create symlinks for ClusterFuzzLite (optional)
cd "$SCRIPT_DIR"
mkdir -p fuzzers
for target in \
    "McuBootSuite.InvokeBootGo" \
    "McuBootSuite.InvokeBootUpgradeLifecycle" \
    "McuBootSuite.BootSurvivesPowerCutsDuringSwap" \
    "McuBootSuite.BootNeverRunsUnauthenticatedImage" \
    "McuBootSuite.SwapSurvivesAnyFlashGeometry" \
    "McuBootSuite.BootParsesArbitraryTlvArea"; do
    
    fuzzer_name="${target//./_}_fuzzer"
    ln -sf "$FUZZ_DIR/build/fuzz_test" "fuzzers/$fuzzer_name" 2>/dev/null || true
    
    # Create a wrapper script for each target
    cat > "fuzzers/$fuzzer_name.sh" << EOF
#!/bin/bash
exec $FUZZ_DIR/build/fuzz_test --fuzz="$target" \"\$@\"
EOF
    chmod +x "fuzzers/$fuzzer_name.sh"
done

echo "ClusterFuzzLite build complete!"
echo "Fuzzers available in: $SCRIPT_DIR/fuzzers/"
