# ClusterFuzzLite Deployment for MCUboot

This directory contains the configuration and scripts for running MCUboot's fuzz tests using ClusterFuzzLite.

## Overview

ClusterFuzzLite is a lightweight, self-hosted version of Google's ClusterFuzz fuzzing infrastructure. It provides:

- **Automatic crash detection and reporting**
- **Corpus management** (maintains and optimizes fuzzing inputs)
- **Crash deduplication**
- **Web-based dashboard** (optional, via external tools)
- **CI/CD integration** (GitHub Actions, GitLab, etc.)

## Directory Structure

```
clusterfuzzlite/
├── README.md           # This file
├── project.yaml        # ClusterFuzzLite project configuration
├── Dockerfile          # Docker image for ClusterFuzzLite
├── docker-compose.yml  # Multi-container Docker setup
├── build.sh            # Build script for fuzz targets
├── run_clusterfuzz.sh  # Main execution script
├── corpus/             # Corpus storage (created at runtime)
├── crashes/            # Crash artifacts (created at runtime)
├── coverage/           # Coverage reports (created at runtime)
└── logs/               # Fuzzing logs (created at runtime)
```

## Quick Start

### Method 1: Using Existing Docker Infrastructure (Recommended)

This method uses the existing Docker setup and wraps it with ClusterFuzzLite functionality.

```bash
# Navigate to the clusterfuzzlite directory
cd /home/gmazurkiewicz/workspace/mcuboot/fuzz/clusterfuzzlite

# Build the fuzz targets (using existing infrastructure)
./build.sh

# Run fuzzing with ClusterFuzzLite wrapper
./run_clusterfuzz.sh
```

### Method 2: Using Docker Compose

For a more isolated setup with all dependencies:

```bash
# Build the ClusterFuzzLite Docker image
cd /home/gmazurkiewicz/workspace/mcuboot/fuzz/clusterfuzzlite
docker compose build

# Run the fuzzer service
docker compose run --rm fuzzer

# Or run the builder first, then the fuzzer
docker compose --profile build run --rm builder
```

### Method 3: Direct Local Execution

Run without Docker (requires all dependencies installed locally):

```bash
# Build the fuzz targets
cd /home/gmazurkiewicz/workspace/mcuboot/fuzz
./build.sh

# Run with ClusterFuzzLite wrapper
cd ../clusterfuzzlite
export CORPUS_DIR=./corpus
export CRASHES_DIR=./crashes
export LOGS_DIR=./logs
export COVERAGE_DIR=./coverage
./run_clusterfuzz.sh
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FUZZ_SECONDS` | 3600 | Duration of each fuzzing session in seconds |
| `MODE` | batch | Fuzzing mode: batch, code-change, parallel, coverage |
| `SANITIZER` | address | Sanitizer to use: address, undefined, or both |
| `PARALLEL_FUZZING` | true | Enable parallel execution |
| `WORKERS` | auto | Number of parallel workers (default: CPU cores) |
| `CORPUS_DIR` | ./corpus | Directory for corpus storage |
| `CRASHES_DIR` | ./crashes | Directory for crash artifacts |
| `LOGS_DIR` | ./logs | Directory for fuzzing logs |
| `COVERAGE_DIR` | ./coverage | Directory for coverage reports |

### Fuzzing Modes

- **batch**: Run all fuzz targets in parallel (default)
- **code-change**: Run each target sequentially (for PR/CI testing)
- **parallel**: Run with limited parallelism (configurable workers)
- **coverage**: Run with coverage instrumentation enabled

### Project Configuration

The `project.yaml` file defines the fuzz targets and their configurations. Each target corresponds to a FuzzTest in `fuzz_test.cpp`.

## Fuzz Targets

The following fuzz targets are configured:

1. **boot_go_fuzzer** - `McuBootSuite.InvokeBootGo`
   - Tests basic boot functionality
   
2. **boot_upgrade_lifecycle_fuzzer** - `McuBootSuite.InvokeBootUpgradeLifecycle`
   - Tests the complete upgrade lifecycle
   
3. **power_cuts_fuzzer** - `McuBootSuite.BootSurvivesPowerCutsDuringSwap`
   - Tests power cut resilience during swap operations
   
4. **never_runs_unauthenticated_fuzzer** - `McuBootSuite.BootNeverRunsUnauthenticatedImage`
   - Tests that unauthenticated images are rejected
   
5. **swap_geometry_fuzzer** - `McuBootSuite.SwapSurvivesAnyFlashGeometry`
   - Tests swap operations with various flash geometries
   
6. **tlv_area_fuzzer** - `McuBootSuite.BootParsesArbitraryTlvArea`
   - Tests TLV (Type-Length-Value) parsing

## Output Directories

All output is stored in the following directories:

- **corpus/**: Fuzzing corpus (inputs that provide coverage)
- **crashes/**: Crash artifacts and test cases
- **logs/**: Fuzzing session logs
- **coverage/**: Coverage reports (if enabled)

These directories are created automatically on first run.

## Integrating with Existing Workflow

The existing fuzzing infrastructure (`fuzz/build.sh`, `fuzz/run.sh`) continues to work. This ClusterFuzzLite setup wraps around it to provide additional features.

To use both:

```bash
# Use existing infrastructure
cd fuzz
./build.sh
./run.sh

# Use ClusterFuzzLite wrapper
cd clusterfuzzlite
./run_clusterfuzz.sh
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: ClusterFuzzLite
on: [push, pull_request]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ClusterFuzzLite
        run: |
          cd fuzz/clusterfuzzlite
          ./build.sh
          ./run_clusterfuzz.sh
        env:
          FUZZ_SECONDS: 600
          MODE: code-change
```

### Using ClusterFuzzLite GitHub Action

For more advanced integration, you can use the official ClusterFuzzLite action:

```yaml
name: ClusterFuzzLite
on: [push, pull_request]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google/clusterfuzzlite/actions/run_fuzzers@v1
        with:
          fuzz-seconds: 600
          mode: code-change
          language: c++
```

## Troubleshooting

### Build Failures

If the build fails:
1. Ensure git submodules are initialized: `git submodule update --init --recursive`
2. Check Docker is running: `docker info`
3. Check disk space: `df -h`

### Fuzzing Hangs

If fuzzing appears to hang:
1. Check logs in the `logs/` directory
2. Try reducing `FUZZ_SECONDS` to a smaller value
3. Try running with fewer workers: `WORKERS=2 ./run_clusterfuzz.sh`

### Permission Issues

If you get permission errors:
1. Ensure proper UID/GID are set: `export HOST_UID=$(id -u) HOST_GID=$(id -g)`
2. Check directory permissions: `ls -la corpus crashes logs`

## Performance Optimization

### Corpus Management
- The corpus is automatically optimized by FuzzTest
- To reset the corpus, delete the `corpus/` directory
- To share corpus between runs, use Docker volumes or persistent storage

### Resource Limits
- Limit CPU usage: `WORKERS=2 ./run_clusterfuzz.sh`
- Limit memory: Use Docker resource limits in `docker-compose.yml`
- Limit disk: Set quotas or use separate disks for corpus/crashes

## Advanced Usage

### Running Specific Targets

To run only specific fuzz targets, modify the `FUZZ_TARGETS` array in `run_clusterfuzz.sh`.

### Custom Build Flags

To use custom build flags, modify `build.sh` or pass environment variables:

```bash
CMAKE_FLAGS="-DCUSTOM_FLAG=ON" ./build.sh
```

### Coverage Reports

To generate coverage reports:

```bash
MODE=coverage ./run_clusterfuzz.sh
```

Then check the `coverage/` directory for reports.

## References

- [ClusterFuzzLite Documentation](https://google.github.io/clusterfuzzlite/)
- [ClusterFuzzLite GitHub](https://github.com/google/clusterfuzzlite)
- [OSS-Fuzz](https://google.github.io/oss-fuzz/)
- [FuzzTest Documentation](https://github.com/google/fuzztest)

## Maintainers

This ClusterFuzzLite deployment is maintained as part of the MCUboot project's fuzzing infrastructure.
