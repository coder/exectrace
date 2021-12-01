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

type handler struct {
	objs BPFObjects

	tp link.Link
	rb *ringbuf.Reader

	startOnce sync.Once
	closeLock sync.Mutex
	closed    chan struct{}
}

var _ Handler = &handler{}

// NewHandler creates a Handler using the given BPFObjects.
func NewHandler(objs BPFObjects) (Handler, error) {
	h := &handler{
		objs: objs,

		startOnce: sync.Once{},
		closeLock: sync.Mutex{},
		closed:    make(chan struct{}),
	}

	// It could be very bad if someone forgot to close this, so we'll try to
	// detect when it doesn't get closed and log a warning.
	stack := debug.Stack()
	runtime.SetFinalizer(h, func(h *handler) {
		err := h.Close()
		if xerrors.Is(err, errhandlerClosed) {
			return
		}

		log.Printf("handler was finalized but was not closed, created at: %s", stack)
		log.Print("handlers must be closed when finished with to avoid leaked kernel resources")
		if err != nil {
			log.Printf("closing handler failed: %+v", err)
		}
	})

	return h, nil
}

// Start loads the eBPF programs and maps into the kernel and starts them.
// You should immediately attach a for loop running `h.Read()` after calling
// this successfully.
func (h *handler) Start() error {
	if h.isClosed() {
		return errhandlerClosed
	}

	var (
		didStart bool
		startErr error
	)
	h.startOnce.Do(func() {
		didStart = true

		// If we don't startup successfully, we need to make sure all of the
		// stuff is cleaned up properly or we'll be leaking kernel resources.
		ok := false
		defer func() {
			if !ok {
				// Best effort.
				_ = h.Close()
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
		h.tp, err = link.Tracepoint("syscalls", "sys_enter_execve", h.objs.enterExecveProg())
		if err != nil {
			startErr = xerrors.Errorf("open tracepoint: %w", err)
			return
		}

		// Create the reader for the event ringbuf.
		h.rb, err = ringbuf.NewReader(h.objs.eventsMap())
		if err != nil {
			startErr = xerrors.Errorf("open ringbuf reader: %w", err)
			return
		}

		ok = true
	})

	if !didStart {
		return xerrors.New("handler has already been started")
	}
	return startErr
}

// Read reads an event from the eBPF program via the ringbuf, parses it and
// returns it. If the *handler is closed during the blocked call, and error that
// wraps io.EOF will be returned.
func (h *handler) Read() (*Event, error) {
	rb := h.rb
	if rb == nil {
		return nil, xerrors.New("ringbuf reader is not initialized, handler may not be open or may have been closed")
	}

	record, err := rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, xerrors.Errorf("handler closed: %w", io.EOF)
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
		Truncated: rawEvent.Truncated != 0,
		Caller: Process{
			PID:  rawEvent.PID,
			Comm: unix.ByteSliceToString(rawEvent.Comm[:]),
			UID:  rawEvent.UID,
			GID:  rawEvent.GID,
			Cgroup: Cgroup{
				ID: rawEvent.Cgroup,
				// TODO: find cgroup paths (needs a lookup cache)
				PathsV1: []string{},
				PathV2:  "",
			},
		},
	}
	for i := range &rawEvent.Argv {
		str := unix.ByteSliceToString(rawEvent.Argv[i][:])
		if strings.TrimSpace(str) != "" {
			ev.Argv = append(ev.Argv, str)
		}
	}

	return ev, nil
}

func (h *handler) isClosed() bool {
	select {
	case <-h.closed:
		return true
	default:
	}

	return false
}

// Close gracefully closes and frees all resources associated with the eBPF
// tracepoints, maps and other resources. Any blocked `Read()` operations will
// return an error that wraps `io.EOF`.
func (h *handler) Close() error {
	h.closeLock.Lock()
	defer h.closeLock.Unlock()
	if h.isClosed() {
		return errhandlerClosed
	}
	close(h.closed)
	runtime.SetFinalizer(h, nil)

	// Close everything started in h.Start() in reverse order.
	var merr error
	if h.rb != nil {
		err := h.rb.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close ringbuf reader: %w", err))
		}
	}
	if h.tp != nil {
		err := h.tp.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close tracepoint: %w", err))
		}
	}

	// It's up to the caller to close h.objs.

	return merr
}
