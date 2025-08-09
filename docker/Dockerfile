# Cloud Run–ready ttyd + tmux interactive EBGuard demo container

##########
# Builder: compile ebguard from source (optionally with LLVM/Clang)
##########
FROM rust:1-bookworm AS builder

ARG WITH_LLVM=false
ENV CARGO_TERM_COLOR=always
WORKDIR /app

# Base build dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    pkg-config \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Optional LLVM/Clang for full-feature build as per README
RUN if [ "$WITH_LLVM" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        llvm-17-dev \
        clang-17 \
      && rm -rf /var/lib/apt/lists/*; \
    fi

# Copy full source first since we don't have Cargo.* files separately
COPY . .

# Build ebguard (no-LLVM basic build by default; full when WITH_LLVM=true)
RUN if [ "$WITH_LLVM" = "true" ]; then \
      LLVM_SYS_170_PREFIX="/usr/lib/llvm-17" CC=clang-17 CXX=clang++-17 cargo build --release; \
    else \
      cargo build --release --no-default-features; \
    fi

##########
# Runtime: minimal Debian with ttyd + tmux and the ebguard binary
##########
FROM debian:stable-slim

# Install minimal runtime dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tmux \
    bash \
 && rm -rf /var/lib/apt/lists/*

# Install latest ttyd Linux x86_64
ARG TTYD_URL="https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.x86_64"
RUN curl -fsSL -o /usr/local/bin/ttyd "${TTYD_URL}" \
 && chmod +x /usr/local/bin/ttyd

# Add EBGuard binary built in the builder stage
COPY --from=builder /app/target/release/ebguard /usr/local/bin/ebguard

# Create samples directory
RUN mkdir -p /opt/ebguard/samples

# Copy samples and rules
COPY samples/*.o samples/*.c /opt/ebguard/samples/
COPY rules.yaml /opt/ebguard/samples/

# Lock down sample directory to read-only for all users
RUN chmod -R a-w /opt/ebguard/samples \
 && find /opt/ebguard/samples -type d -exec chmod 0555 {} \; \
 && find /opt/ebguard/samples -type f -exec chmod 0444 {} \;

# Add restricted wrapper shell
COPY docker/ebguardsh /usr/local/bin/ebguardsh
RUN chmod +x /usr/local/bin/ebguardsh

# Permissions
RUN chmod +x /usr/local/bin/ebguard

# Non-root user for Cloud Run best practices
RUN useradd -m -u 10001 -s /bin/bash app
USER app
WORKDIR /home/app

# Expose the service port (Cloud Run defaults to 8080)
EXPOSE 8080

# Run ttyd with more permissive options
CMD ["ttyd", "--writable", "--ping-interval", "100", "-p", "8080", "-t", "fontSize=14", "-t", "theme={\"background\": \"#1a1a1a\"}", "tmux", "new-session", "-A", "-s", "ebguard", "/usr/local/bin/ebguardsh"]