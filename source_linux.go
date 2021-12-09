//go:build linux
// +build linux

package exectrace

import (
	"embed"
	"io"
	"os"
	"path/filepath"
	"text/template"

	"golang.org/x/xerrors"
)

const (
	// programDir is the dir within SourceFiles that contains the eBPF source
	// code.
	programDir = "bpf"
	// programFile is the name of the C source file containing the eBPF program.
	programFile = "handler.c"
)

var (
	tplFiles = [...]string{programFile}
)

// SourceFiles contains all of the C source files and headers needed to compile
// the eBPF program.
//go:embed bpf/*.c bpf/*.h
var SourceFiles embed.FS

// copySource copys all of the files from SourceFiles to the specified
// directory.
func copySource(opts CompileOptions) error {
	// Copy template files first.
	tplFilesMap := make(map[string]struct{}, len(tplFiles))
	for _, f := range tplFiles {
		src := filepath.Join(programDir, f)
		dest := filepath.Join(opts.TempDir, f)
		err := copySourceFileTpl(src, dest, &opts)
		if err != nil {
			return xerrors.Errorf("extract file %q from executable to dest %q: %w", src, dest, err)
		}

		tplFilesMap[f] = struct{}{}
	}

	// Copy non-template files.
	ents, err := SourceFiles.ReadDir(programDir)
	if err != nil {
		return xerrors.Errorf("ReadDir on embedded FS: %w", err)
	}
	for _, ent := range ents {
		if !ent.Type().IsRegular() {
			continue
		}
		if _, ok := tplFilesMap[ent.Name()]; ok {
			continue
		}

		src := filepath.Join(programDir, ent.Name())
		dest := filepath.Join(opts.TempDir, ent.Name())
		err = copySourceFile(src, dest)
		if err != nil {
			return xerrors.Errorf("extract file %q from executable to dest %q: %w", src, dest, err)
		}
	}

	return nil
}

func copySourceFile(src, dest string) error {
	return copySourceFileTpl(src, dest, nil)
}

func copySourceFileTpl(src, dest string, opts *CompileOptions) error {
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

	// If there are no options provided, copy normally.
	if opts == nil {
		_, err = io.Copy(destFile, srcFile)
		if err != nil {
			return xerrors.Errorf("copy file from source %q to destination file %q: %w", src, dest, err)
		}
		return nil
	}

	// Template the file before writing.
	raw, err := io.ReadAll(srcFile)
	if err != nil {
		return xerrors.Errorf("read all data from source file %q: %w", src, err)
	}

	tpl, err := template.New("exectrace").Parse(string(raw))
	if err != nil {
		return xerrors.Errorf("parse template for source file %q: %w", src, err)
	}

	err = tpl.Execute(destFile, opts)
	if err != nil {
		return xerrors.Errorf("execute parsed template with CompileOptions: %w", err)
	}

	return nil
}
