//go:build linux
// +build linux

package exectrace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/xerrors"
)

const outputFile = "bpf_program.o"

// CompileProgram compiles and returns the compiled output of the exectrace
// eBPF program.
//
// This code is heavily adapted from the `bpf2go` utility that comes with
// cilium/ebpf, which is licensed under the MIT license:
// https://github.com/cilium/ebpf/blob/13667bdb8f164c32ae1b85e7130552dd93e86dfd/cmd/bpf2go/compile.go
func CompileProgram(ctx context.Context, opts CompileOptions) ([]byte, error) {
	// Setup temp compilation dir.
	var (
		err       error
		deleteDir bool
	)
	if opts.TempDir == "" {
		opts.TempDir, err = os.MkdirTemp("", "exectrace_compile_")
		if err != nil {
			return nil, xerrors.Errorf("create temp dir: %w", err)
		}

		// Best effort. We try harder at the end of the compilation if
		// successful.
		defer func() { _ = os.RemoveAll(opts.TempDir) }()
	}
	err = copySource(opts.TempDir)
	if err != nil {
		return nil, xerrors.Errorf("copy source files from binary to temporary compilation dir: %w", err)
	}

	// Determine build target.
	if opts.Endianness == "" {
		opts.Endianness = NativeEndianness
	}
	var target string
	switch opts.Endianness {
	case BigEndian:
		target = "bpfeb"
	case LittleEndian:
		target = "bpfel"
	default:
		return nil, xerrors.Errorf("unknown endianness %q, could not determine build target", opts.Endianness)
	}

	// Args that will be supplied to the compiler.
	args := []string{
		// Code needs to be optimized, otherwise the verifier will often fail to
		// understand it.
		"-O2",
		// Clang defaults to mcpu=probe which checks the kernel that we are
		// compiling on. This isn't appropriate for ahead of time compiled code
		// so force the most compatible version.
		"-mcpu=v1",
		// We always want BTF to be generated, so enforce debug symbols.
		"-g",
		// Enable lots of warnings, and treat all warnings as fatal errors.
		"-Wall", "-Wextra", "-Werror",
		// Don't include the clang version.
		"-fno-ident",
		// Don't output the current directory into debug info.
		"-fdebug-compilation-dir", ".",

		"-target", target,
		"-c", "./" + ProgramFile,
		"-o", "./" + outputFile,
	}

	// Compilation is very quick, even on computers with baby CPUs, so we set a
	// build timeout of 1 minute.
	compileCtx, compileCancel := context.WithTimeout(ctx, time.Minute)
	defer compileCancel()
	//nolint:gosec // intended for callers to be able to change the args and compiler path
	cmd := exec.CommandContext(compileCtx, opts.Compiler, args...)
	cmd.Dir = opts.TempDir

	compilerOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, xerrors.Errorf(
			"running compiler failed: %v %v: %w:\n\n%s", opts.Compiler, strings.Join(args, " "), err, compilerOutput,
		)
	}

	// Read the output file into memory so we can use it. The output file isn't
	// very large (in the tens of KBs range), so this is fine for now.
	outputPath := filepath.Join(opts.TempDir, outputFile)
	out, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, xerrors.Errorf("read output binary from compiler %q: %w", outputPath, err)
	}

	if deleteDir {
		err = os.RemoveAll(opts.TempDir)
		if err != nil {
			return nil, xerrors.Errorf("remove temporary output directory %q: %w", opts.TempDir, err)
		}
	}

	return out, nil
}
