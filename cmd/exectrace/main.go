package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kballard/go-shellquote"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/coder/exectrace"
)

func main() {
	err := rootCmd().Execute()
	if err != nil {
		log.Fatalf("failed to run command: %+v", err)
	}
}

func rootCmd() *cobra.Command {
	var (
		pidNS        uint32
		outputFormat string
	)

	var cmd = &cobra.Command{
		Use:   "exectrace",
		Short: "exectrace logs all exec calls on the system.",
		Run: func(cmd *cobra.Command, args []string) {
			if outputFormat != "text" && outputFormat != "json" {
				log.Fatalf(`output format must be "text" or "json", got %q`, outputFormat)
			}

			err := run(pidNS, outputFormat)
			if err != nil {
				log.Fatalf("run exectrace: %+v", err)
			}
		},
	}

	cmd.Flags().Uint32VarP(&pidNS, "pid-ns", "p", 0, "PID NS ID to filter events from, you can get this by doing `readlink /proc/self/ns/pid`")
	cmd.Flags().StringVarP(&outputFormat, "output", "f", "text", "Output format, text or json")

	return cmd
}

func run(pidNS uint32, outputFormat string) error {
	t, err := exectrace.New(&exectrace.TracerOpts{
		PidNS: pidNS,
	})
	if err != nil {
		return xerrors.Errorf("start tracer: %w", err)
	}
	defer t.Close()

	// When we get a SIGTERM we should close the tracer so the loop exits.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals

		log.Print("signal received, closing tracer")
		err := t.Close()
		if err != nil {
			log.Fatalf("error closing tracer: %+v", err)
		}
	}()

	enc := json.NewEncoder(os.Stdout)

	log.Println("Waiting for events..")
	for {
		event, err := t.Read()
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

			_, _ = fmt.Printf(
				"[%v, comm=%q, uid=%v, gid=%v] %v%v\n",
				event.PID, event.Comm, event.UID, event.GID,
				shellquote.Join(event.Argv...), ellipsis,
			)
			continue
		}
		err = enc.Encode(event)
		if err != nil {
			log.Printf("error writing event as JSON: %+v", err)
			continue
		}
	}
}
