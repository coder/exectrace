package exectrace

import (
	"os"
	"os/exec"
	"testing"

	"github.com/DataDog/ebpfbench"
	"github.com/stretchr/testify/require"

	"github.com/coder/exectrace"
)

func BenchmarkExectraceBase(b *testing.B) {
	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		b.Fatal("must be run as root")
	}

	// Start tracer.
	tracer, err := exectrace.New(&exectrace.TracerOpts{
		LogFn: func(uid, gid, pid uint32, logLine string) {
			b.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
		},
	})
	require.NoError(b, err)
	defer tracer.Close()

	eb := ebpfbench.NewEBPFBenchmark(b)
	defer eb.Close()

	eb.ProfileProgram(tracer.FD(), "enter_execve")
	eb.Run(func(b *testing.B) {
		// NOTE: the actual iteration count in the final logs might be higher
		// than b.N because the program runs on every execve syscall (even ones
		// that don't originate from the benchmarked code).
		//
		// ebpfbench will still report the correct number of iterations and the
		// average time per iteration.
		for i := 0; i < b.N; i++ {
			cmd := exec.Command("true")
			err := cmd.Run()
			require.NoError(b, err)

			_, err = tracer.Read()
			require.NoError(b, err)
			// Can't verify the process here because we are not filtering and
			// other processes on the system will cause any checks to fail.
		}
	})
}

// NOTE: you should probably run this benchmark with ./bench.sh or `make bench`.
func BenchmarkExectracePIDNSFilter(b *testing.B) {
	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		b.Fatal("must be run as root")
	}

	pidNS, err := exectrace.GetPidNS()
	require.NoError(b, err)

	// Start tracer.
	tracer, err := exectrace.New(&exectrace.TracerOpts{
		PidNS: pidNS,
		LogFn: func(uid, gid, pid uint32, logLine string) {
			b.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
		},
	})
	require.NoError(b, err)
	defer tracer.Close()

	eb := ebpfbench.NewEBPFBenchmark(b)
	defer eb.Close()

	eb.ProfileProgram(tracer.FD(), "enter_execve")
	eb.Run(func(b *testing.B) {
		// NOTE: iteration count can end up higher than b.N, see above.
		//
		// Because filtered events take less time to process in the kernel, this
		// does impact the benchmark results. The average time per iteration
		// reported will be lower than it should be. If you run with a high
		// iteration count the effect should be mostly invisible, however.
		for i := 0; i < b.N; i++ {
			cmd := exec.Command("true")
			err := cmd.Run()
			require.NoError(b, err)

			event, err := tracer.Read()
			require.NoError(b, err)
			require.Equal(b, "true", event.Argv[0])
		}
	})
}

func BenchmarkExectracePIDNSFilterNoHit(b *testing.B) {
	// This test must be run as root so we can start exectrace.
	if os.Geteuid() != 0 {
		b.Fatal("must be run as root")
	}

	pidNS, err := exectrace.GetPidNS()
	require.NoError(b, err)

	// Start tracer.
	tracer, err := exectrace.New(&exectrace.TracerOpts{
		// Use a nonsense PID NS so we don't match any processes.
		PidNS: pidNS + 1,
		LogFn: func(uid, gid, pid uint32, logLine string) {
			b.Errorf("tracer error log (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
		},
	})
	require.NoError(b, err)
	defer tracer.Close()

	eb := ebpfbench.NewEBPFBenchmark(b)
	defer eb.Close()

	eb.ProfileProgram(tracer.FD(), "enter_execve")
	eb.Run(func(b *testing.B) {
		// NOTE: iteration count can end up higher than b.N, see above.
		//
		// Since every event is a no hit because the filter doesn't match
		// anything, results should not be impacted.
		for i := 0; i < b.N; i++ {
			cmd := exec.Command("true")
			err := cmd.Run()
			require.NoError(b, err)
		}
	})
}
