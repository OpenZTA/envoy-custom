# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS builder
ARG TARGETARCH
ARG BAZELISK_VERSION=1.25.0
ARG BUILD_JOBS=3
ARG TEST_JOBS=1
ARG BAZEL_CONFIG=openzta
ARG BUILD_SCM_REVISION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake bison ca-certificates clang-19 cmake curl flex g++ git \
    gettext libclang-19-dev libc++-19-dev libc++abi-19-dev libtool lld-19 \
    llvm-19 llvm-19-dev make ninja-build openjdk-17-jdk-headless patch \
    pkg-config python3 python3-venv unzip zip zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL --retry 5 \
       "https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-${TARGETARCH}" \
       -o /usr/local/bin/bazel && chmod 755 /usr/local/bin/bazel
WORKDIR /src
COPY . .
ENV CC=/usr/bin/clang-19 CXX=/usr/bin/clang++-19
RUN --mount=type=cache,target=/root/.cache \
    tools/setup_clang.sh /usr/lib/llvm-19 && \
    BUILD_SCM_REVISION="${BUILD_SCM_REVISION:-$(bash tools/source_revision.sh)}" BUILD_SCM_STATUS=Modified \
    bazel --host_jvm_args=-Xmx1536m build -c opt --config="${BAZEL_CONFIG}" --jobs="${BUILD_JOBS}" //:envoy && \
    cp -L bazel-bin/envoy /usr/local/bin/openzta-envoy && \
    /usr/lib/llvm-19/bin/llvm-strip --strip-debug /usr/local/bin/openzta-envoy

FROM builder AS verification
RUN --mount=type=cache,target=/root/.cache \
    BUILD_SCM_REVISION="${BUILD_SCM_REVISION:-$(bash tools/source_revision.sh)}" BUILD_SCM_STATUS=Modified \
    bazel --host_jvm_args=-Xmx1536m test -c opt --config="${BAZEL_CONFIG}" --jobs="${TEST_JOBS}" \
    --test_output=errors //test/...

FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS runtime-base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libc++1-19 libc++abi1-19 libunwind-19 && \
    rm -rf /var/lib/apt/lists/* && mkdir -p /etc/envoy && \
    useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin envoy
USER 10001:10001
EXPOSE 8443 8443/udp 2222 2525
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl --fail --silent --unix-socket /tmp/envoy-admin.sock http://localhost/ready || exit 1
ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]

# Explicit opt-out target for an authorized deferred C++ run. It still requires
# a real binary build; release evidence must record the missing C++ suite.
FROM runtime-base AS runtime-candidate
ARG BUILD_SCM_REVISION
LABEL org.opencontainers.image.title="OpenZTA Proxy" \
      org.opencontainers.image.revision="${BUILD_SCM_REVISION}" \
      ru.openzta.verification.cpp="deferred"
COPY --from=builder /usr/local/bin/openzta-envoy /usr/local/bin/envoy

# Default target retains the full C++ gate for normal release builds.
FROM runtime-base AS verified
ARG BUILD_SCM_REVISION
LABEL org.opencontainers.image.title="OpenZTA Proxy" \
      org.opencontainers.image.revision="${BUILD_SCM_REVISION}" \
      ru.openzta.verification.cpp="passed"
COPY --from=verification /usr/local/bin/openzta-envoy /usr/local/bin/envoy
