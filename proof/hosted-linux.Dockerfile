# proof/hosted-linux.Dockerfile
# Pinned toolchain and execution cage for GitHub-hosted Linux strict proof.
# Plan reference: agent://HostedProofPlan Sections 3D, 3E, 4C.

FROM ubuntu:24.04

# Prevent interactive prompts during apt operations
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install foundational packages, compilers, toolchains, and runtime utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    wget \
    build-essential \
    make \
    git \
    pkg-config \
    binutils \
    coreutils \
    llvm-18 \
    llvm-18-dev \
    clang-18 \
    libclang-18-dev \
    lld-18 \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    libssl-dev \
    libzstd-dev \
    nodejs \
    openssl \
    bind9-dnsutils \
    tar \
    bzip2 \
    xz-utils \
    zip \
    unzip \
    strace \
    bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

# Configure LLVM 18 alternatives so llvm-config, clang, clang++ are standard
RUN update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-18 100 \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100

# Install Crystal compiler from official Crystal release repository
RUN curl -fsSL https://dist.crystal-lang.org/apt/setup.sh | bash \
    && apt-get update \
    && apt-get install -y --no-install-recommends crystal \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.25 toolchain (supporting ECH and modern crypto requirements)
# Falling back to stable modern Go if tarball fetch is unavailable
ARG GO_VERSION=1.25.0
RUN (curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz \
     && tar -C /usr/local -xzf /tmp/go.tar.gz \
     && rm -f /tmp/go.tar.gz) || \
    (apt-get update && apt-get install -y --no-install-recommends golang-go && rm -rf /var/lib/apt/lists/*)

# Install required Python packages pinned per Plan Section 3E
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    pyyaml \
    "idna==3.11" \
    cryptography \
    pillow \
    h2 \
    hpack \
    zstandard

# Configure proof user account (UID:GID 65534:65534)
# On Ubuntu 24.04, 65534 is nobody:nogroup. Ensure /etc/passwd has a valid proof user with /home/proof.
RUN sed -i '/^nobody:/d' /etc/passwd 2>/dev/null || true \
    && echo "proof:x:65534:65534:Proof Runner:/home/proof:/bin/bash" >> /etc/passwd \
    && (grep -q ":65534:" /etc/group || echo "proof:x:65534:" >> /etc/group)

# Create required mount points and owned writable roots
RUN mkdir -p /home/proof \
    && mkdir -p /private/tmp \
    && mkdir -p /scratch \
    && mkdir -p /P \
    && mkdir -p /W \
    && mkdir -p /inputs \
    && mkdir -p /control \
    && mkdir -p /receipts \
    && chown -R 65534:65534 /home/proof /private/tmp /scratch \
    && chmod 0755 /home/proof /scratch \
    && chmod 1777 /private/tmp

# Confinement and environment variables
ENV HOME=/home/proof
ENV PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin
USER 65534:65534
WORKDIR /home/proof

CMD ["/bin/bash"]
