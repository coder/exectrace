// This file is licensed under the Coder Enterprise License. Please see
// ../../../LICENSE.enterprise.
package main

import (
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/slogjson"
	exectracewrapper "github.com/coder/exectrace/enterprise"
)

func main() {
	app := root()

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}

func root() *cli.App {
	return &cli.App{
		Name: "exectrace",
		Usage: "Run exectrace tracing, printing a log line for each process " +
			"launched in the workspace.",
		Description: "Waits for the PidNS to be sent from the sibling " +
			"container to http://<addr>, then logs all exec calls in the " +
			"specified PidNS to stderr using the exectrace library.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: "init-address",
				Usage: "The HTTP listen address that the binary listens on " +
					"temporarily at startup for the PidNS. Once a PidNS is " +
					"received, this server is automatically closed.",
				// We use this port because it's uncommon.
				Value: "0.0.0.0:56123",
			},
			&cli.DurationFlag{
				Name: "startup-timeout",
				Usage: "The maximum duration that the process will wait for " +
					"PidNS to be received during startup before timing out.",
				// We use 15 minutes as the default as Kubernetes starts
				// containers out of order, so it might start this container
				// long before the workspace container is ready to start.
				Value: 15 * time.Minute,
			},
			&cli.BoolFlag{
				Name: "use-local-pidns",
				Usage: "Use the local PidNS instead of waiting for one over " +
					"HTTP. This should only be used if it's difficult to " +
					"send the PidNS over HTTP (e.g. due to network policies) " +
					"and requires the workspace and exectrace container to " +
					"share a PidNS.",
			},
			&cli.StringSliceFlag{
				Name: "label",
				Usage: "Add these labels to all logged events. Labels are in " +
					"the form of key=value.",
			},
		},
		Action: func(ctx *cli.Context) error {
			// TODO: more flags for controlling logging
			log := slog.Make(slogjson.Sink(os.Stderr)).Leveled(slog.LevelDebug)

			// Add labels from flags.
			rawLabels := ctx.StringSlice("label")
			labels := make(map[string]string, len(rawLabels))
			for _, l := range rawLabels {
				vals := strings.SplitN(l, "=", 2)
				if len(vals) != 2 {
					return xerrors.Errorf("invalid label %q", l)
				}

				labels[strings.TrimSpace(vals[0])] = strings.TrimSpace(vals[1])
			}
			log = log.With(slog.F("labels", labels))

			log.Debug(ctx.Context, "starting exectrace")
			err := exectracewrapper.Run(ctx.Context, log, exectracewrapper.Options{
				UseLocalPidNS:     ctx.Bool("use-local-pidns"),
				InitListenAddress: ctx.String("init-address"),
				StartupTimeout:    ctx.Duration("startup-timeout"),
			})
			if err != nil {
				return xerrors.Errorf("run exectrace: %w", err)
			}

			return nil
		},
	}
}
