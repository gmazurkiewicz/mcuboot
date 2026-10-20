# ClusterFuzzLite Dockerfile for MCUboot
# Extends the existing fuzz infrastructure with ClusterFuzzLite

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
        git \
        cmake \
        clang-19 \
        g++ \
        build-essential \
        ninja-build \
        python3 \
        python3-pip \
        python3-venv \
        wget \
        curl \
    && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 100 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set up Python virtual environment
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Install ClusterFuzzLite and dependencies
RUN pip install --upgrade pip && \
    pip install clusterfuzzlite

# Clone ClusterFuzzLite repository (for additional tools)
RUN git clone https://github.com/google/clusterfuzzlite.git /clusterfuzzlite

# Copy MCUboot source
WORKDIR /workspace
COPY .. /workspace

# Build MCUboot fuzz targets
WORKDIR /workspace/fuzz
RUN ./build.sh

# Set up ClusterFuzzLite working directory
WORKDIR /workspace/fuzz/clusterfuzzlite

# Create directories for persistent storage
RUN mkdir -p /workspace/fuzz/clusterfuzzlite/corpus
RUN mkdir -p /workspace/fuzz/clusterfuzzlite/crashes
RUN mkdir -p /workspace/fuzz/clusterfuzzlite/coverage
RUN mkdir -p /workspace/fuzz/clusterfuzzlite/logs

# Set environment variables
ENV MCUBOOT_DIR=/workspace
ENV FUZZ_DIR=/workspace/fuzz
ENV CLUSTERFUZZLITE_DIR=/clusterfuzzlite
ENV CORPUS_DIR=/workspace/fuzz/clusterfuzzlite/corpus
ENV CRASHES_DIR=/workspace/fuzz/clusterfuzzlite/crashes
ENV COVERAGE_DIR=/workspace/fuzz/clusterfuzzlite/coverage
ENV LOGS_DIR=/workspace/fuzz/clusterfuzzlite/logs

# Default command
CMD ["/bin/bash"]
