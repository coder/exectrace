//go:build linux
// +build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/kballard/go-shellquote"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"cdr.dev/exectrace"
)

// suitableCompilers contains suitable clang compilers that exectrace will look
// for if a compiler isn't specified in the flags.
var suitableCompilers = []string{
	"clang-13",
	"clang-12",
	"clang-11",
	"clang",
}

func main() {
	err := rootCmd().Execute()
	if err != nil {
		log.Fatalf("failed to run command: %+v", err)
	}
}

func rootCmd() *cobra.Command {
	var (
		compiler     string
		outputFormat string
	)

	var cmd = &cobra.Command{
		Use:   "exectrace",
		Short: "exectrace logs all exec calls on the system.",
		Run: func(cmd *cobra.Command, args []string) {
			if outputFormat != "text" && outputFormat != "json" {
				log.Fatalf(`output format must be "text" or "json", got %q`, outputFormat)
			}

			err := run(cmd.Context(), compiler, outputFormat)
			if err != nil {
				log.Fatalf("run exectrace: %+v", err)
			}
		},
	}

	cmd.Flags().StringVarP(&compiler, "compiler", "c", "", "Compiler executable name or path (defaults to the first suitable clang compiler found)")
	cmd.Flags().StringVarP(&outputFormat, "output", "f", "text", "Output format, text or json")

	return cmd
}

func findCompiler() (string, error) {
	for _, c := range suitableCompilers {
		path, err := exec.LookPath(c)
		if err == nil {
			return path, nil
		}
	}

	return "", xerrors.New("could not find suitable compiler in PATH")
}

func run(ctx context.Context, compiler, outputFormat string) error {
	var err error
	if compiler == "" {
		compiler, err = findCompiler()
		if err != nil {
			return err
		}

		log.Printf("using detected compiler %q", compiler)
	}

	// CompileProgram calls the specified compiler and returns the bytes of the
	// compiled BPF ELF.
	out, err := exectrace.CompileProgram(ctx, exectrace.CompileOptions{
		Compiler: compiler,
	})
	if err != nil {
		return xerrors.Errorf("compile program: %w", err)
	}

	// Loads the BPF objects into the kernel.
	objs, err := exectrace.LoadBPFObjectsBytes(out)
	if err != nil {
		return xerrors.Errorf("load BPF objects from compiled bytes: %w", err)
	}

	// Handler exposes a handy `h.Read()` method for reading events from the
	// eBPF program running in the kernel, used below.
	h, err := exectrace.NewHandler(objs)
	if err != nil {
		return xerrors.Errorf("create handler: %w", err)
	}
	defer h.Close()

	// Starts the eBPF program in the kernel.
	err = h.Start()
	if err != nil {
		return xerrors.Errorf("start handler: %w", err)
	}

	// When we get a SIGTERM we should close the handler so the loop exits.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals

		log.Print("signal received, closing handler")
		err := h.Close()
		if err != nil {
			log.Fatalf("error closing handler: %+v", err)
		}
	}()

	enc := json.NewEncoder(os.Stdout)

	log.Println("Waiting for events..")
	for {
		event, err := h.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			log.Printf("error reading from reader: %+v", err)
			continue
		}

		if outputFormat == "text" {
			ellipsis := ""
			if event.Truncated {
				ellipsis = "..."
			}

			_, _ = fmt.Printf("[pid=%v, cgroup.id=%v, comm=%q] %v%v\n",
				event.Caller.PID, event.Caller.Cgroup.ID, event.Caller.Comm,
				shellquote.Join(event.Argv...), ellipsis,
			)
		} else {
			err = enc.Encode(event)
			if err != nil {
				log.Printf("error writing event as JSON: %+v", err)
				continue
			}
		}
	}
}
