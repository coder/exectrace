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

.PHONY: clean
clean:
	rm -rf bpf/handler-bpfeb.o bpf/handler-bpfel.o

.PHONY: all
all: bpf/handler-bpfeb.o bpf/handler-bpfel.o

# bpfeb is big endian, bpfel is little endian.
bpf/handler-bpfeb.o bpf/handler-bpfel.o: bpf/*.h bpf/*.c
	cd ./bpf
	# Run clang with the following options:
	# -O2:
	#   Optimize the code so the BTF verifier can understand it properly.
	# -mcpu=v1:
	#   Clang defaults to mcpu=probe which checks the kernel that we are
	#   compiling on. This isn't appropriate for ahead of time compiled code so
    #   force the most compatible version.
	# -g:
	#   We always want BTF to be generates, so enforce debug symbols.
	# -Wall -Wextra -Werror:
	#   Enable lots of warnings, and treat all warnings as fatal build errors.
	# -fno-ident:
	#   Don't include the clang version.
	# -fdebug-compilation-dir .:
	#   Don't output the current directory into debug info.
	# -target
	#   This is set to bpfeb or bpfel based on the build target.
	$(CXX) \
		$(CXXFLAGS) \
		-O2 \
		-mcpu=v1 \
		-g \
		-Wall -Wextra -Werror \
		-fno-ident \
		-fdebug-compilation-dir . \
		-target "$(@F:handler-%.o=%)" \
		-c ./handler.c \
		-o "$(@F)"

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
lint/c:
	clang-tidy-13 \
		-checks=-*,cert-*,linuxkernel-*,clang-analyzer-*,llvm-*,performance-*,portability-*,readability-* \
		-warnings-as-errors=* \
		./bpf/handler.c
