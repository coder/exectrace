package exectrace

import (
	"embed"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

const (
	// ProgramDir is the dir within SourceFiles that contains the eBPF source
	// code.
	ProgramDir = "bpf"
	// ProgramFile is the name of the C source file containing the eBPF program.
	ProgramFile = "handler.c"
)

// SourceFiles contains all of the C source files and headers needed to compile
// the eBPF program.
//go:embed bpf/*.c bpf/*.h
var SourceFiles embed.FS

// CompileOptions contains options to pass to functions that compile the eBPF
// program used by exectrace.
type CompileOptions struct {
	// Compiler contains the executable name or full path to the C compiler. A
	// recent version of clang is recommended (i.e. clang-11+). Required.
	Compiler string

	// Endianness to compile the program for. If not specified, the current
	// system endianness of the system will be used.
	Endianness Endianness
	// TempDir is where the compilation inputs will be placed to pass to the
	// compiler. This is the working directory where the compilation will take
	// place. Header and source files will be copied to this directory out of
	// the binary; if they already exist then an error will be returned instead
	// of overwriting them.
	//
	// If empty, a temporary dir will be created and automatically cleaned up on
	// error or success. If specified, the dir will not be automatically
	// deleted.
	TempDir string
}

// copySource copys all of the files from SourceFiles to the specified
// directory.
func copySource(destDir string) error {
	ents, err := SourceFiles.ReadDir(ProgramDir)
	if err != nil {
		return xerrors.Errorf("ReadDir on embedded FS: %w", err)
	}

	for _, ent := range ents {
		if !ent.Type().IsRegular() {
			continue
		}

		err = copySourceFile(filepath.Join(ProgramDir, ent.Name()), filepath.Join(destDir, ent.Name()))
		if err != nil {
			return xerrors.Errorf("extract file %q from executable to dest dir %q: %w", ent.Name(), destDir, err)
		}
	}

	return nil
}

func copySourceFile(src, dest string) error {
	// Open the file from the embedded FS.
	srcFile, err := SourceFiles.Open(src)
	if err != nil {
		return xerrors.Errorf("open source file %q in embedded FS: %w", src, err)
	}
	defer srcFile.Close()

	// Ensure the parent directory of the file.
	dir := filepath.Dir(dest)
	err = os.MkdirAll(dir, 0o700)
	if err != nil {
		return xerrors.Errorf("ensure parent directory %q for file %q in %q: %w", dir, src, dest, err)
	}

	// Open the destination file with O_CREATE and O_EXCL, which means the
	// file will be created for us, and if it already existed an error will
	// be returned.
	destFile, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return xerrors.Errorf("create (excl) destination file %q: %w", dest, err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return xerrors.Errorf("copy file from source %q to destination file %q: %w", src, dest, err)
	}

	return nil
}
