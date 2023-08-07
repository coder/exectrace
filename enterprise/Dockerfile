# This is a multui-arch Dockerfile, so it cannot have ANY "RUN" commands as it's
# cross-compiled. All binaries are cross-compiled using the host's Go toolchain
# and then copied into the build context.
#
# This uses Ubuntu instead of Alpine Linux because the binaries are compiled
# with cgo due to dependencies requiring cgo.
FROM ubuntu:latest

# LABEL doesn't add any real layers so it's fine (and easier) to do it here than
# in the build script.
ARG CODER_VERSION
LABEL \
	org.opencontainers.image.title="Coder v2 Exectrace" \
	org.opencontainers.image.description="A tool for tracing launched processes inside Coder workspaces." \
	org.opencontainers.image.url="https://github.com/coder/exectrace/enterprise" \
	org.opencontainers.image.source="https://github.com/coder/exectrace/enterprise" \
	org.opencontainers.image.version="$CODER_VERSION"

COPY exectrace /opt/exectrace

USER 0:0
WORKDIR /

ENTRYPOINT [ "/opt/exectrace", "run" ]
