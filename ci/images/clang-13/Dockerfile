FROM ubuntu:focal-20211006

ARG RELEASE=focal

COPY llvm-snapshot.gpg.key /llvm-snapshot.gpg.key

RUN set -eux && \
    apt update && \
    apt install -y \
        apt-transport-https \
        ca-certificates \
        gnupg && \
    \
    echo "deb http://apt.llvm.org/$RELEASE llvm-toolchain-$RELEASE-13 main" \
        > /etc/apt/sources.list.d/clang-13.list && \
    apt-key add /llvm-snapshot.gpg.key && \
    \
    apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y \
        clang-13 \
        clang-tools-13 \
        clang-tidy-13
