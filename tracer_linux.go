//go:build linux
// +build linux

package exectrace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

// These constants are defined in `bpf/handler.c` and must be kept in sync.
const (
	ARGLEN  = 32
	ARGSIZE = 1024
)

// event contains details about each exec call, sent from the eBPF program to
// userspace through a perf ring buffer. This type must be kept in sync with
// `event_t` in `bpf/handler.c`.
type event struct {
	// Details about the process being launched.
	Filename [ARGSIZE]byte
	Argv     [ARGLEN][ARGSIZE]byte
	Argc     uint32
	UID      uint32
	GID      uint32
	PID      uint32

	// Name of the calling process.
	Comm [ARGSIZE]byte
}

type tracer struct {
	objs BPFObjects

	tp link.Link
	rb *ringbuf.Reader

	startOnce sync.Once
	closeLock sync.Mutex
	closed    chan struct{}
}

var _ Tracer = &tracer{}

// NewTracer creates a Tracer using the given BPFObjects.
func NewTracer(objs BPFObjects) (Tracer, error) {
	t := &tracer{
		objs: objs,

		startOnce: sync.Once{},
		closeLock: sync.Mutex{},
		closed:    make(chan struct{}),
	}

	// It could be very bad if someone forgot to close this, so we'll try to
	// detect when it doesn't get closed and log a warning.
	stack := debug.Stack()
	runtime.SetFinalizer(t, func(t *tracer) {
		err := t.Close()
		if xerrors.Is(err, errTracerClosed) {
			return
		}

		log.Printf("tracer was finalized but was not closed, created at: %s", stack)
		log.Print("tracers must be closed when finished with to avoid leaked kernel resources")
		if err != nil {
			log.Printf("closing tracer failed: %+v", err)
		}
	})

	return t, nil
}

// Start loads the eBPF programs and maps into the kernel and starts them.
// You should immediately attach a for loop running `h.Read()` after calling
// this successfully.
func (t *tracer) Start() error {
	if t.isClosed() {
		return errTracerClosed
	}

	var (
		didStart bool
		startErr error
	)
	t.startOnce.Do(func() {
		didStart = true

		// If we don't startup successfully, we need to make sure all of the
		// stuff is cleaned up properly or we'll be leaking kernel resources.
		ok := false
		defer func() {
			if !ok {
				// Best effort.
				_ = t.Close()
			}
		}()

		// Allow the current process to lock memory for eBPF resources. This
		// does nothing on 5.11+ kernels which don't need this.
		err := rlimit.RemoveMemlock()
		if err != nil {
			startErr = xerrors.Errorf("remove memlock: %w", err)
			return
		}

		// Attach the eBPF program to the `sys_enter_execve` tracepoint, which
		// is triggered at the beginning of each `execve()` syscall.
		t.tp, err = link.Tracepoint("syscalls", "sys_enter_execve", t.objs.enterExecveProg())
		if err != nil {
			startErr = xerrors.Errorf("open tracepoint: %w", err)
			return
		}

		// Create the reader for the event ringbuf.
		t.rb, err = ringbuf.NewReader(t.objs.eventsMap())
		if err != nil {
			startErr = xerrors.Errorf("open ringbuf reader: %w", err)
			return
		}

		ok = true
	})

	if !didStart {
		return xerrors.New("tracer has already been started")
	}
	return startErr
}

// Read reads an event from the eBPF program via the ringbuf, parses it and
// returns it. If the *tracer is closed during the blocked call, and error that
// wraps io.EOF will be returned.
func (t *tracer) Read() (*Event, error) {
	rb := t.rb
	if rb == nil {
		return nil, xerrors.New("ringbuf reader is not initialized, tracer may not be open or may have been closed")
	}

	record, err := rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, xerrors.Errorf("tracer closed: %w", io.EOF)
		}

		return nil, xerrors.Errorf("read from ringbuf: %w", err)
	}

	// Parse the ringbuf event entry into an event structure.
	var rawEvent event
	err = binary.Read(bytes.NewBuffer(record.RawSample), NativeEndian, &rawEvent)
	if err != nil {
		return nil, xerrors.Errorf("parse raw ringbuf entry into event struct: %w", err)
	}

	ev := &Event{
		Filename:  unix.ByteSliceToString(rawEvent.Filename[:]),
		Argv:      []string{}, // populated below
		Truncated: rawEvent.Argc == ARGLEN+1,
		PID:       rawEvent.PID,
		UID:       rawEvent.UID,
		GID:       rawEvent.GID,
		Comm:      unix.ByteSliceToString(rawEvent.Comm[:]),
	}

	// Copy only the args we're allowed to read from the array. If we read more
	// than rawEvent.Argc, we could be copying non-zeroed memory.
	argc := int(rawEvent.Argc)
	if argc > ARGLEN {
		argc = ARGLEN
	}
	for i := 0; i < argc; i++ {
		str := unix.ByteSliceToString(rawEvent.Argv[i][:])
		if strings.TrimSpace(str) != "" {
			ev.Argv = append(ev.Argv, str)
		}
	}

	return ev, nil
}

func (t *tracer) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
	}

	return false
}

// Close gracefully closes and frees all resources associated with the eBPF
// tracepoints, maps and other resources. Any blocked `Read()` operations will
// return an error that wraps `io.EOF`.
func (t *tracer) Close() error {
	t.closeLock.Lock()
	defer t.closeLock.Unlock()
	if t.isClosed() {
		return errTracerClosed
	}
	close(t.closed)
	runtime.SetFinalizer(t, nil)

	// Close everything started in h.Start() in reverse order.
	var merr error
	if t.rb != nil {
		err := t.rb.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close ringbuf reader: %w", err))
		}
	}
	if t.tp != nil {
		err := t.tp.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close tracepoint: %w", err))
		}
	}

	// It's up to the caller to close t.objs.

	return merr
}
