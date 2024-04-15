.DEFAULT_GOAL := handlers

# Use a single bash shell for each job, and immediately exit on failure
SHELL := bash
.SHELLFLAGS := -ceu
.ONESHELL:

# This doesn't work on directories.
# See https://stackoverflow.com/questions/25752543/make-delete-on-error-for-directory-targets
.DELETE_ON_ERROR:

# Don't print the commands in the file unless you specify VERBOSE. This is
# essentially the same as putting "@" at the start of each line.
ifndef VERBOSE
.SILENT:
endif

CXX = clang-13

.PHONY: handlers
handlers: bpf/handler-bpfeb.o bpf/handler-bpfel.o

.PHONY: clean
clean: clean-enterprise
	rm -rf bpf/handler-bpfeb.o bpf/handler-bpfel.o

ci/.clang-image: ci/images/clang-13/Dockerfile ci/scripts/clang_image.sh
	./ci/scripts/clang_image.sh
	touch ci/.clang-image

# bpfeb is big endian, bpfel is little endian.
bpf/handler-bpfeb.o bpf/handler-bpfel.o: bpf/*.h bpf/*.c ci/.clang-image ci/scripts/build_handler.sh
	./ci/scripts/build_handler.sh "$(@F)"

.PHONY: fmt
fmt: fmt/go fmt/prettier

.PHONY: fmt/go
fmt/go:
	go fmt ./...
	cd enterprise
	go fmt ./...

.PHONY: fmt/prettier
fmt/prettier:
	# Config file: .prettierrc
	prettier -w .

.PHONY: lint
lint: lint/go lint/c lint/shellcheck

.PHONY: lint/go
lint/go: lint/go/linux lint/go/other

.PHONY: lint/go/linux
lint/go/linux:
	# Config file: .golangci.yml
	golangci-lint run ./...
	cd enterprise
	golangci-lint run ./...

.PHONY: lint/go/other
lint/go/other:
	# The windows and darwin builds include the same files.
	# Config file: .golangci.yml
	GOOS=windows golangci-lint run ./...
	# Enterprise dir does not support Windows or Darwin.

.PHONY: lint/c
lint/c: ci/.clang-image
	# Config file: .clang-tidy
	./ci/scripts/clang.sh clang-tidy-13 --config-file ../.clang-tidy ./handler.c

.PHONY: lint/shellcheck
lint/shellcheck:
	./ci/scripts/shellcheck.sh

.PHONY: test
test: test/go test/go-enterprise

.PHONY: test/go
test/go:
	go test -exec sudo -v -count 1 ./...

.PHONY: test/go-enterprise
test/go-enterprise:
	cd enterprise
	go test -exec sudo -v -count 1 ./...

.PHONY: bench
bench:
	go clean -testcache
	COUNT=10000 ./bench/bench.sh

include Makefile.enterprise
