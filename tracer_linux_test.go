//go:build linux
// +build linux

package exectrace_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/coder/exectrace"
)

//nolint:paralleltest
func TestExectrace(t *testing.T) {
	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		t.Fatal("must be run as root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tracer, err := exectrace.New(&exectrace.TracerOpts{
		LogFn: func(uid, gid, pid uint32, logLine string) {
			t.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
		},
	})
	require.NoError(t, err)
	defer tracer.Close()

	// Launch processes.
	const (
		expected = "hello exectrace basic test"
		uid      = 1000
		gid      = 2000
	)
	args := []string{"sh", "-c", "# " + expected}
	filename, err := exec.LookPath(args[0])
	require.NoError(t, err)
	processDone := spamProcess(ctx, t, args, func(cmd *exec.Cmd) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uid,
				Gid: gid,
			},
		}
	})

	event := getLogEntry(ctx, t, tracer, expected)
	require.Equal(t, filename, event.Filename, "event.Filename")
	require.Equal(t, args, event.Argv, "event.Argv")
	require.False(t, event.Truncated, "event.Truncated is true")
	require.NotEqualValues(t, event.PID, 0, "event.PID should not be 0")
	require.NotEqual(t, event.PID, os.Getpid(), "event.PID should not be the parent PID")
	require.EqualValues(t, event.UID, uid, "event.UID should match custom UID")
	require.EqualValues(t, event.GID, gid, "event.GID should match custom GID")

	// Comm can either be parent.Argv[0] or the parent full binary path.
	executable, err := os.Executable()
	require.NoError(t, err)
	if event.Comm != executable {
		require.Equalf(t, filepath.Base(os.Args[0]), event.Comm, "event.Comm should match parent argv[0] (does not match executable %q)", executable)
	}

	cancel()
	<-processDone
}

func TestExectraceTruncatedArgs(t *testing.T) {
	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		t.Fatal("must be run as root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tracer, err := exectrace.New(&exectrace.TracerOpts{
		LogFn: func(uid, gid, pid uint32, logLine string) {
			t.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
		},
	})
	require.NoError(t, err)
	defer tracer.Close()

	const expected = "hello exectrace overflow test"
	args := []string{"echo", expected}

	// Exectrace only captures the first 32 arguments of each process.
	for i := 0; i < 30; i++ {
		args = append(args, fmt.Sprint(i))
	}
	args = append(args, "final")
	require.Len(t, args, 33)

	// Launch processes.
	processDone := spamProcess(ctx, t, args, nil)
	event := getLogEntry(ctx, t, tracer, expected)

	// Should only hold the first 32 args, and truncated should be true.
	require.Len(t, event.Argv, 32)
	require.Equal(t, args[:32], event.Argv, "event.Argv")
	require.True(t, event.Truncated, "event.Truncated is false")

	cancel()
	<-processDone
}

func TestExectraceTruncatedLongArg(t *testing.T) {
	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		t.Fatal("must be run as root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tracer, err := exectrace.New(&exectrace.TracerOpts{
		LogFn: func(uid, gid, pid uint32, logLine string) {
			t.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
		},
	})
	require.NoError(t, err)
	defer tracer.Close()

	// We only record the first 1024 bytes of each argument, so use an arg
	// that's longer.
	const expected = "hello exectrace arg length test"
	args := []string{"echo", expected, strings.Repeat("a", 1025), "final"}

	// Launch processes.
	processDone := spamProcess(ctx, t, args, nil)
	event := getLogEntry(ctx, t, tracer, expected)

	// Should only hold the first 1021 chars of the long arg with a trailing
	// "...".
	args[2] = args[2][:1021] + "..."
	require.Equal(t, args, event.Argv, "event.Argv")
	require.True(t, event.Truncated, "event.Truncated is false")

	cancel()
	<-processDone
}

//nolint:paralleltest
func TestExectracePIDNS(t *testing.T) {
	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		t.Fatal("must be run as root")
	}

	//nolint:paralleltest
	t.Run("Same", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Filter by the current PidNS.
		pidNS, err := exectrace.GetPidNS()
		require.NoError(t, err)
		tracer, err := exectrace.New(&exectrace.TracerOpts{
			PidNS: pidNS,
			LogFn: func(uid, gid, pid uint32, logLine string) {
				t.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
			},
		})
		require.NoError(t, err)
		defer tracer.Close()

		// Launch processes.
		const expected = "hello exectrace pidns test same"
		args := []string{"sh", "-c", "# " + expected}
		processDone := spamProcess(ctx, t, args, nil)

		_ = getLogEntry(ctx, t, tracer, expected)

		cancel()
		<-processDone
	})

	//nolint:paralleltest
	t.Run("Child", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Filter by the current PidNS.
		pidNS, err := exectrace.GetPidNS()
		require.NoError(t, err)
		tracer, err := exectrace.New(&exectrace.TracerOpts{
			PidNS: pidNS,
			LogFn: func(uid, gid, pid uint32, logLine string) {
				t.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
			},
		})
		require.NoError(t, err)
		defer tracer.Close()

		// Launch processes.
		const expected = "hello exectrace pidns test child"
		args := []string{"sh", "-c", "# " + expected}
		processDone := spamProcess(ctx, t, args, func(cmd *exec.Cmd) {
			cmd.SysProcAttr = &syscall.SysProcAttr{
				// Subprocess will be in a child PID namespace.
				Cloneflags: syscall.CLONE_NEWPID,
			}
		})

		_ = getLogEntry(ctx, t, tracer, expected)

		cancel()
		<-processDone
	})

	//nolint:paralleltest
	t.Run("Different", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Filter by a slightly different PidNS.
		pidNS, err := exectrace.GetPidNS()
		require.NoError(t, err)
		tracer, err := exectrace.New(&exectrace.TracerOpts{
			PidNS: pidNS + 1,
			LogFn: func(uid, gid, pid uint32, logLine string) {
				t.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
			},
		})
		require.NoError(t, err)
		defer tracer.Close()

		// Launch processes.
		const expected = "hello exectrace pidns test different"
		args := []string{"sh", "-c", "# " + expected}
		processDone := spamProcess(ctx, t, args, nil)

		// We should not see any events. Read events for up to 5 seconds.
		go func() {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			<-ctx.Done()
			_ = tracer.Close()
		}()
		event, err := tracer.Read()
		if err == nil {
			t.Fatalf("unexpected event: %+v", event)
		}
		if !xerrors.Is(err, io.EOF) {
			t.Fatalf("tracer.Read: %v", err)
		}

		cancel()
		<-processDone
	})
}

// spamProcess runs the given command every 100ms. The returned channel is
// closed when the goroutine exits (either if there's a problem or if the
// context is canceled).
func spamProcess(ctx context.Context, t *testing.T, args []string, mutateCmdFn func(*exec.Cmd)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			//nolint:gosec
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			if mutateCmdFn != nil {
				mutateCmdFn(cmd)
			}
			_, err := cmd.CombinedOutput()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				t.Errorf("command launch failure in spamProcess: %+v", err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	return done
}

// getLogEntry returns the next log entry from the tracer which contains the
// given string in it's arguments.
func getLogEntry(ctx context.Context, t *testing.T, tracer exectrace.Tracer, expected string) *exectrace.Event {
	t.Helper()

	// Kill the tracer when the context expires.
	go func() {
		<-ctx.Done()
		_ = tracer.Close()
	}()

	// Consume log lines until we find our process.
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for process")
		default:
		}

		event, err := tracer.Read()
		if err != nil {
			t.Fatalf("tracer.Read: %v", err)
		}

		t.Logf("event: %+v\n", event)
		joined := strings.Join(event.Argv, " ")
		if !strings.Contains(joined, expected) {
			t.Logf("above event does not match: %q does not contain %q", joined, expected)
			continue
		}
		t.Logf("above event matches: %q contains %q", joined, expected)
		return event
	}
}
