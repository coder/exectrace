FROM ubuntu:focal

ARG DEBIAN_FRONTEND=noninteractive

RUN set -eux && \
    apt update && \
    apt install -y \
        apt-transport-https \
        ca-certificates \
        gnupg

# Install clang-13
COPY llvm.gpg /usr/share/keyrings/llvm.gpg
COPY llvm.list /etc/apt/sources.list.d/llvm.list
RUN set -eux && \
    apt update && \
    apt install -y \
        clang-13 \
        clang-tools-13 \
        clang-tidy-13
