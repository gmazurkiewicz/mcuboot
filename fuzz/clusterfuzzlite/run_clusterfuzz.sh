#!/bin/bash

# ClusterFuzzLite runner script for MCUboot
# This script wraps the existing fuzz_test binary with ClusterFuzzLite functionality

set -e

# Export host user IDs for Docker
if [ -z "$HOST_UID" ]; then
    export HOST_UID=$(id -u)
fi
if [ -z "$HOST_GID" ]; then
    export HOST_GID=$(id -g)
fi

# Directory setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(dirname "$SCRIPT_DIR")/.."
FUZZ_DIR="$WORKSPACE_DIR/fuzz"
BUILD_DIR="$FUZZ_DIR/build"

# Ensure build exists
if [ ! -f "$BUILD_DIR/fuzz_test" ]; then
    echo "Building fuzz_test..."
    cd "$FUZZ_DIR"
    ./build.sh
    cd "$SCRIPT_DIR"
fi

# Environment variables with defaults
FUZZ_SECONDS=${FUZZ_SECONDS:-3600}  # 1 hour default
MODE=${MODE:-batch}
SANITIZER=${SANITIZER:-address}
PARALLEL_FUZZING=${PARALLEL_FUZZING:-true}
WORKERS=${WORKERS:-$(nproc 2>/dev/null || echo 4)}

# Set default directories if not provided
CORPUS_DIR=${CORPUS_DIR:-$SCRIPT_DIR/corpus}
CRASHES_DIR=${CRASHES_DIR:-$SCRIPT_DIR/crashes}
LOGS_DIR=${LOGS_DIR:-$SCRIPT_DIR/logs}
COVERAGE_DIR=${COVERAGE_DIR:-$SCRIPT_DIR/coverage}

# Fuzz targets from project.yaml
FUZZ_TARGETS=(
    "McuBootSuite.InvokeBootGo"
    "McuBootSuite.InvokeBootUpgradeLifecycle"
    "McuBootSuite.BootSurvivesPowerCutsDuringSwap"
    "McuBootSuite.BootNeverRunsUnauthenticatedImage"
    "McuBootSuite.SwapSurvivesAnyFlashGeometry"
    "McuBootSuite.BootParsesArbitraryTlvArea"
)

echo "========================================"
echo "ClusterFuzzLite for MCUboot"
echo "========================================"
echo "Mode: $MODE"
echo "Fuzz Seconds: $FUZZ_SECONDS"
echo "Sanitizer: $SANITIZER"
echo "Parallel Fuzzing: $PARALLEL_FUZZING"
echo "Workers: $WORKERS"
echo "Corpus Dir: $CORPUS_DIR"
echo "Crashes Dir: $CRASHES_DIR"
echo "Logs Dir: $LOGS_DIR"
echo "========================================"

# Create output directories if they don't exist
mkdir -p "$CORPUS_DIR" "$CRASHES_DIR" "$LOGS_DIR" "$COVERAGE_DIR"

# Function to run a single fuzz target
run_fuzz_target() {
    local target="$1"
    local log_file="$LOGS_DIR/fuzz_${target//./_}.log"
    
    echo "[$(date)] Starting fuzz for $target"
    echo "[$(date)] Output: $log_file"
    
    # Run the fuzzer with the specified target
    $BUILD_DIR/fuzz_test \
        --fuzz="$target" \
        --fuzz_for="${FUZZ_SECONDS}s" \
        --corpus_dir="$CORPUS_DIR/$target" \
        --crash_dir="$CRASHES_DIR/$target" \
        --log_file="$log_file" \
        2>&1 | tee -a "$log_file"
    
    echo "[$(date)] Completed fuzz for $target"
}

# Function to run fuzz target with ClusterFuzzLite wrapper
run_clusterfuzz_target() {
    local target="$1"
    local fuzzer_name="${target//./_}_fuzzer"
    
    echo "[$(date)] Starting ClusterFuzzLite for $target"
    
    # Use python3 with the venv if available
    local python_cmd="python3"
    if [ -f "/venv/bin/python3" ]; then
        python_cmd="/venv/bin/python3"
    fi
    
    # Run using ClusterFuzzLite's batch_fuzz.py
    $python_cmd /clusterfuzzlite/batch_fuzz.py \
        --fuzz-targets="$fuzzer_name" \
        --workers=1 \
        --fuzz-seconds="$FUZZ_SECONDS" \
        --mode="$MODE" \
        /workspace \
        2>&1 | tee "$LOGS_DIR/clusterfuzz_${fuzzer_name}.log"
    
    echo "[$(date)] Completed ClusterFuzzLite for $target"
}

# Main execution
case "$MODE" in
    "batch")
        echo "Running in batch mode..."
        for target in "${FUZZ_TARGETS[@]}"; do
            run_fuzz_target "$target" &
        done
        wait
        echo "All batch fuzzing completed"
        ;;
    "code-change")
        echo "Running in code-change mode..."
        # Run each target sequentially for code-change detection
        for target in "${FUZZ_TARGETS[@]}"; do
            run_fuzz_target "$target"
        done
        echo "Code-change fuzzing completed"
        ;;
    "parallel")
        echo "Running in parallel mode with $WORKERS workers..."
        # Use parallel execution with limited workers
        active_jobs=0
        for target in "${FUZZ_TARGETS[@]}"; do
            # If we've hit the parallel limit, wait for one to finish
            while [ "$active_jobs" -ge "$WORKERS" ]; do
                wait -n
                active_jobs=$((active_jobs - 1))
            done
            
            run_fuzz_target "$target" &
            active_jobs=$((active_jobs + 1))
        done
        
        # Wait for all remaining jobs
        wait
        echo "Parallel fuzzing completed"
        ;;
    "coverage")
        echo "Running in coverage mode..."
        # Enable coverage flags
        export FUZZ_COVERAGE=1
        
        for target in "${FUZZ_TARGETS[@]}"; do
            run_fuzz_target "$target"
        done
        
        echo "Coverage fuzzing completed"
        # Generate coverage report
        if [ -d "$COVERAGE_DIR" ]; then
            echo "Coverage reports in: $COVERAGE_DIR"
        fi
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Supported modes: batch, code-change, parallel, coverage"
        exit 1
        ;;
esac

# Print summary
echo ""
echo "========================================"
echo "ClusterFuzzLite Summary"
echo "========================================"
echo "Logs: $LOGS_DIR"
echo "Crashes: $CRASHES_DIR"
echo "Corpus: $CORPUS_DIR"

# Count crash files
crash_count=$(find "$CRASHES_DIR" -type f -name "*.log" -o -name "*.txt" 2>/dev/null | wc -l)
echo "Crash files found: $crash_count"

# Show recent crashes
if [ "$crash_count" -gt 0 ]; then
    echo ""
    echo "Recent crashes:"
    find "$CRASHES_DIR" -type f \( -name "*.log" -o -name "*.txt" \) 2>/dev/null | sort -r | head -10
fi

echo "========================================"
echo "Done!"
