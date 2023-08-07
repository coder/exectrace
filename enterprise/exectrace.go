/*
 * This file is licensed under the Coder Enterprise License. Please see
 * ./LICENSE.
 */
package exectracewrapper

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kballard/go-shellquote"
	"golang.org/x/xerrors"
	"k8s.io/utils/mount"

	"cdr.dev/slog"
	"github.com/coder/exectrace"
)

const (
	pidNSPath = "/proc/self/ns/pid"

	debugFS           = "debugfs"
	debugFSMountpoint = "/sys/kernel/debug"
	traceFS           = "tracefs"
	traceFSMountpoint = debugFSMountpoint + "/tracing"
)

var (
	nonNumericRegex = regexp.MustCompile(`[^\d]`)
)

type Options struct {
	UseLocalPidNS     bool
	InitListenAddress string
	StartupTimeout    time.Duration
}

func Run(ctx context.Context, log slog.Logger, opts Options) error {
	var (
		err   error
		pidNS uint32
	)
	if opts.UseLocalPidNS {
		log.Debug(ctx, "using local PidNS")
		pidNS, err = getPidNS()
		if err != nil {
			return xerrors.Errorf("get current pidns: %w", err)
		}
	} else {
		waitCtx, waitCancel := context.WithTimeout(ctx, opts.StartupTimeout)
		defer waitCancel()

		// Wait for the PidNS to be sent to us from the workspace container.
		log.Debug(ctx, "waiting for PidNS", slog.F("addr", opts.InitListenAddress), slog.F("timeout", opts.StartupTimeout))
		pidNS, err = waitForExectracePidNS(waitCtx, opts.InitListenAddress)
		if err != nil {
			return xerrors.Errorf("wait for PidNS at %q: %w", opts.InitListenAddress, err)
		}
	}
	log.Debug(ctx, "got PidNS", slog.F("pid_ns", pidNS))

	// We need to make sure that debugfs is mounted at /sys/kernel/debug and
	// tracefs is mounted at /sys/kernel/debug/tracing.
	log.Debug(ctx, "preparing environment for eBPF tracing")
	err = ensureVirtualMountpoint(debugFS, debugFSMountpoint, nil)
	if err != nil {
		return xerrors.Errorf("ensure debugfs mounted: %w", err)
	}
	err = ensureVirtualMountpoint(traceFS, traceFSMountpoint, nil)
	if err != nil {
		return xerrors.Errorf("ensure tracefs mounted: %w", err)
	}

	log.Debug(ctx, "starting tracer")
	tracer, err := exectrace.New(&exectrace.TracerOpts{
		PidNS: pidNS,
	})
	if err != nil {
		return xerrors.Errorf("create tracer: %w", err)
	}
	defer func() {
		err := tracer.Close()
		if err != nil && !xerrors.Is(err, io.EOF) {
			log.Error(ctx, "failed to close tracer on exit", slog.Error(err))
		}
	}()

	events := make(chan *exectrace.Event, 1)
	errCh := make(chan error, 1)
	go func() {
		const attempts = 10
		for {
			// Fatal after 10 consecutive read errors.
			for i := 1; ; i++ {
				event, err := tracer.Read()
				if err != nil {
					log.Warn(ctx, "failed to read event from tracer", slog.Error(err))
					if i == attempts {
						log.Error(ctx, "failed to read event after many attempts", slog.F("attempts", attempts))
						errCh <- err
						return
					}
					continue
				}

				events <- event
				break
			}
		}
	}()

	// Setup a signal handler so we can gracefully exit.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	signal.Notify(signals, syscall.SIGTERM)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-signals:
			log.Warn(ctx, "received signal, exiting")
			return nil
		case err := <-errCh:
			log.Error(ctx, "closing tracer due to error", slog.Error(err))
			return err
		case event := <-events:
			log.Info(ctx, "exec",
				// Construct a simple string field so people don't need to write
				// queries against the argv array.
				slog.F("cmdline", shellquote.Join(event.Argv...)),
				slog.F("event", event),
			)
		}
	}
}

// waitForExectracePidNS starts a HTTP server on listenAddr and waits until it
// gets POSTed a uint32, then closes the server and returns it.
func waitForExectracePidNS(ctx context.Context, listenAddr string) (uint32, error) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return 0, xerrors.Errorf("listen %q on tcp: %w", listenAddr, err)
	}
	defer l.Close()

	return waitForExectracePidNSListener(ctx, l)
}

func waitForExectracePidNSListener(ctx context.Context, l net.Listener) (uint32, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		pidNS uint32
		valid bool
		srv   = &http.Server{
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       5 * time.Second,
			Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				writeError := func(rw http.ResponseWriter, status int, msg string) {
					rw.Header().Set("Content-Type", "text/plain")
					rw.WriteHeader(status)
					_, _ = rw.Write([]byte(msg))
				}
				if r.Method != "POST" || (r.URL.Path != "" && r.URL.Path != "/") {
					writeError(rw, http.StatusBadRequest, "This server only accepts POST requests at /")
					return
				}

				ct := r.Header.Get("Content-Type")
				if ct != "" && ct != "text/plain" {
					writeError(rw, http.StatusBadRequest, "This server only accepts text/plain requests")
					return
				}

				// Read 16 bytes from the body, max uint32 is 10 chars so this
				// is plenty.
				body, err := io.ReadAll(io.LimitReader(r.Body, 16))
				if err != nil {
					writeError(rw, http.StatusInternalServerError, "Failed to read request body: "+err.Error())
					return
				}

				// Parse the body as a uint32.
				val, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 32)
				if err != nil {
					writeError(rw, http.StatusBadRequest, "Failed to parse request body as uint32 string: "+err.Error())
					return
				}

				pidNS = uint32(val)
				valid = true
				rw.WriteHeader(http.StatusNoContent)
				cancel()
			}),
		}
	)
	defer srv.Close()

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	err := srv.Serve(l)
	if !xerrors.Is(err, http.ErrServerClosed) {
		return 0, xerrors.Errorf("start server: %w", err)
	}
	if !valid {
		return 0, xerrors.Errorf("did not receive a PidNS from the workspace in time: %w", ctx.Err())
	}

	return pidNS, nil
}

func ensureVirtualMountpoint(mountType, dest string, opts []string) error {
	mounter := &mount.Mounter{}
	if len(opts) == 0 {
		// The default on the server I tested this on.
		opts = []string{"rw", "nosuid", "nodev", "noexec", "relatime"}
	}

	// Find an existing mount.
	mounts, err := mounter.List()
	if err != nil {
		return xerrors.Errorf("list mounts: %w", err)
	}
	for _, m := range mounts {
		// NOTE: We don't check the device (i.e. source) because it doesn't
		// matter for virtual filesystems. Sometimes it's mounted as "none",
		// sometimes it's the same as the mount type.

		if m.Path == dest {
			if m.Type != mountType {
				return xerrors.Errorf("mount already exists at %q with incorrect type %q", m.Path, m.Type)
			}

			return nil
		}
	}

	// Create the new mount.
	err = os.MkdirAll(dest, 0o744)
	if err != nil {
		return xerrors.Errorf("mkdir -p %q: %w", dest, err)
	}
	err = mounter.Mount(mountType, dest, mountType, opts)
	if err != nil {
		return xerrors.Errorf("mount -t %q -o %q %q %q: %w", mountType, strings.Join(opts, ","), mountType, dest, err)
	}

	return nil
}

// getPidNS returns the inum of the PidNS used by the current process.
func getPidNS() (uint32, error) {
	rawPidNS, err := os.Readlink(pidNSPath)
	if err != nil {
		return 0, xerrors.Errorf("readlink %v: %w", pidNSPath, err)
	}

	rawPidNS = nonNumericRegex.ReplaceAllString(rawPidNS, "")
	pidNS, err := strconv.ParseUint(rawPidNS, 10, 32)
	if err != nil {
		return 0, xerrors.Errorf("parse PidNS %v to uint32: %w", rawPidNS, err)
	}

	return uint32(pidNS), nil
}
