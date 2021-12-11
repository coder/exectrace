SHELL := bash
# Exit on failure
.SHELLFLAGS := -ceu
.DELETE_ON_ERROR:
.ONESHELL:

# Specify the verbose flag to see all command output.
ifndef VERBOSE
.SILENT:
endif

CXX = clang-13

.PHONY: all
all: bpf/handler-bpfeb.o bpf/handler-bpfel.o

.PHONY: clean
clean:
	rm -rf bpf/handler-bpfeb.o bpf/handler-bpfel.o

ci/.clang-image: ci/images/clang-13/Dockerfile
	./ci/scripts/clang_image.sh
	touch ci/.clang-image

# bpfeb is big endian, bpfel is little endian.
bpf/handler-bpfeb.o bpf/handler-bpfel.o: bpf/*.h bpf/*.c ci/.clang-image
	./ci/scripts/build_handler.sh "$(@F)"

.PHONY: fmt
fmt: fmt/go fmt/prettier

.PHONY: fmt/go
fmt/go:
	go fmt ./...

.PHONY: fmt/prettier
fmt/prettier:
	prettier -w .

.PHONY: lint
lint: lint/go lint/c

.PHONY: lint/go
lint/go: lint/go/linux lint/go/other

.PHONY: lint/go/linux
lint/go/linux:
	golangci-lint run ./...

.PHONY: lint/go/other
lint/go/other:
    # The windows and darwin builds include the same files.
	GOOS=windows golangci-lint run ./...

.PHONY: lint/c
lint/c: ci/.clang-image
	./ci/scripts/clang.sh clang-tidy-13 \
		-checks=-*,cert-*,linuxkernel-*,clang-analyzer-*,llvm-*,performance-*,portability-*,readability-* \
		-warnings-as-errors=* \
		./handler.c
