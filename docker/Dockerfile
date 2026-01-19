# Multi-stage build for envoy-custom
# Stage 1: Build environment with all dependencies

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (from .github/workflows/test-linux.yaml)
# Plus autotools for OpenSSH foreign_cc build
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    virtualenv \
    llvm-19 \
    llvm-19-linker-tools \
    llvm-19-runtime \
    llvm-19-tools \
    libllvm19 \
    clang-19 \
    clang-tools-19 \
    libclang1-19 \
    libclang-cpp19 \
    libc++-19-dev \
    libc++abi1-19 \
    lld-19 \
    # Autotools for OpenSSH build (autoreconf)
    autoconf \
    automake \
    libtool \
    # Additional build tools
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Bazelisk
RUN curl -fsSL -o /usr/local/bin/bazel \
    https://github.com/bazelbuild/bazelisk/releases/download/v1.25.0/bazelisk-linux-amd64 \
    && chmod +x /usr/local/bin/bazel

WORKDIR /build

# Copy source code
COPY . .

# Setup clang toolchain
RUN ./tools/setup_clang.sh /usr/lib/llvm-19

# Build envoy (this takes a long time - 30-60+ minutes)
RUN bazel build -c opt //:envoy

# Stage 2: Minimal runtime image
FROM ubuntu:24.04 AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the statically-linked binary
COPY --from=builder /build/bazel-bin/envoy /usr/local/bin/envoy

# Create config directory
RUN mkdir -p /etc/envoy/keys

# Create non-root user
RUN useradd -r -u 1001 -s /sbin/nologin envoy

USER envoy

EXPOSE 2222 8080 9901

ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]
