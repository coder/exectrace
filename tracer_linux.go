//go:build linux
// +build linux

package exectrace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

// These constants are defined in `bpf/handler.c` and must be kept in sync.
const (
	arglen     = 32
	argsize    = 1024
	logfmtsize = 1024
	logarglen  = 3
)

var errTracerClosed = xerrors.New("tracer is closed")

// event contains details about each exec call, sent from the eBPF program to
// userspace through a perf ring buffer. This type must be kept in sync with
// `event_t` in `bpf/handler.c`.
type event struct {
	// Details about the process being launched.
	Filename [argsize]byte
	Argv     [arglen][argsize]byte
	Argc     uint32
	UID      uint32
	GID      uint32
	PID      uint32

	// Name of the calling process.
	Comm [argsize]byte
}

// logEntry contains each kernel log entry from the logs ringbuf. This type must
// be kept in sync with `log_entry_t` in `bpf/handler.c`.
type logEntry struct {
	UID uint32
	GID uint32
	PID uint32
	Fmt [logfmtsize]byte
	// Args are uint32s but depending on the format string, they may be
	// interpreted as int32s instead.
	Arg [logarglen]uint32
}

type tracer struct {
	opts *TracerOpts

	objs *bpfObjects
	tp   link.Link

	rbEvents *ringbuf.Reader
	rbLogs   *ringbuf.Reader

	closeLock sync.Mutex
	closed    chan struct{}
}

var _ Tracer = &tracer{}

// New instantiates all of the BPF objects into the running kernel, starts
// tracing, and returns the created Tracer. After calling this successfully, the
// caller should immediately attach a for loop running `h.Read()`.
//
// The returned Tracer MUST be closed to avoid leaking kernel resources.
func New(opts *TracerOpts) (Tracer, error) {
	if opts == nil {
		opts = &TracerOpts{}
	}
	if opts.LogFn == nil {
		opts.LogFn = func(uid, gid, pid uint32, logLine string) {
			log.Printf("error log from exectrace tracer (uid=%v, gid=%v, pid=%v): %s", uid, gid, pid, logLine)
		}
	}

	objs, err := loadBPFObjects()
	if err != nil {
		return nil, xerrors.Errorf("load BPF objects: %w", err)
	}

	t := &tracer{
		opts:     opts,
		objs:     objs,
		tp:       nil,
		rbEvents: nil,
		rbLogs:   nil,

		closeLock: sync.Mutex{},
		closed:    make(chan struct{}),
	}
	err = t.start()
	if err != nil {
		// Best effort.
		_ = t.Close()
		return nil, xerrors.Errorf("start tracer: %w", err)
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

func (t *tracer) FD() int {
	return t.objs.EnterExecveProg.FD()
}

func (t *tracer) start() error {
	// If we don't startup successfully, we need to make sure all of the stuff
	// is cleaned up properly or we'll be leaking kernel resources.
	ok := false
	defer func() {
		if !ok {
			// Best effort.
			_ = t.Close()
		}
	}()

	// Allow the current process to lock memory for eBPF resources. This does
	// nothing on 5.11+ kernels which don't need this.
	err := rlimit.RemoveMemlock()
	if err != nil {
		return xerrors.Errorf("remove memlock: %w", err)
	}

	// Set filter options on the filters map.
	if t.opts.PidNS != 0 {
		err = t.objs.FiltersMap.Update(uint32(0), t.opts.PidNS, ebpf.UpdateAny)
		if err != nil {
			return xerrors.Errorf("apply PID NS filter to eBPF map: %w", err)
		}
	}

	// Attach the eBPF program to the `sys_enter_execve` tracepoint, which
	// is triggered at the beginning of each `execve()` syscall.
	t.tp, err = link.Tracepoint("syscalls", "sys_enter_execve", t.objs.EnterExecveProg, nil)
	if err != nil {
		return xerrors.Errorf("open tracepoint: %w", err)
	}

	// Create the reader for the event ringbuf.
	t.rbEvents, err = ringbuf.NewReader(t.objs.EventsMap)
	if err != nil {
		return xerrors.Errorf("open events ringbuf reader: %w", err)
	}

	// Create the reader for the log ringbuf.
	t.rbLogs, err = ringbuf.NewReader(t.objs.LogsMap)
	if err != nil {
		return xerrors.Errorf("open logs ringbuf reader: %w", err)
	}

	// Start slurping up logs.
	go t.readLogs(t.rbLogs, t.opts.LogFn)

	ok = true
	return nil
}

// Read reads an event from the eBPF program via the ringbuf, parses it and
// returns it. If the *tracer is closed during the blocked call, and error that
// wraps io.EOF will be returned.
func (t *tracer) Read() (*Event, error) {
	rb := t.rbEvents
	if rb == nil {
		return nil, xerrors.Errorf("events ringbuf reader is not initialized: %w", io.EOF)
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
		Truncated: rawEvent.Argc == arglen+1,
		PID:       rawEvent.PID,
		UID:       rawEvent.UID,
		GID:       rawEvent.GID,
		Comm:      unix.ByteSliceToString(rawEvent.Comm[:]),
	}

	// Copy only the args we're allowed to read from the array. If we read more
	// than rawEvent.Argc, we could be copying non-zeroed memory.
	argc := int(rawEvent.Argc)
	if argc > arglen {
		argc = arglen
	}
	for i := 0; i < argc; i++ {
		str := unix.ByteSliceToString(rawEvent.Argv[i][:])
		// The copy in the eBPF code only copies 1023 bytes.
		if len(str) >= argsize-1 {
			ev.Truncated = true
			// Set final 3 bytes to "..." to indicate truncation.
			str = str[:argsize-3] + "..."
		}
		if strings.TrimSpace(str) != "" {
			ev.Argv = append(ev.Argv, str)
		}
	}

	return ev, nil
}

func (t *tracer) readLogs(rbLogs *ringbuf.Reader, logFn func(uid, gid, pid uint32, logLine string)) {
	defer func() {
		if r := recover(); r != nil {
			logFn(0, 0, 0, fmt.Sprintf("panic in (*tracer).readLogs() goroutine: %v", r))
			_ = t.Close()
		}
	}()

	for {
		record, err := rbLogs.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}

			logFn(0, 0, 0, fmt.Sprintf("read from logs ringbuf: %+v", err))
			continue
		}

		var logEntry logEntry
		err = binary.Read(bytes.NewBuffer(record.RawSample), NativeEndian, &logEntry)
		if err != nil {
			logFn(0, 0, 0, fmt.Sprintf("parse raw ringbuf entry into logEntry struct: %+v", err))
			continue
		}

		// Format the log line.
		// 1. Find all %u and %d directives in the string (this is all we
		//    support).
		// 2. For each:
		//    1. If it's a %u, replace it with the next uint32 in the args.
		//    2. If it's a %d, cast the next uint32 to an int32 and replace.
		logLine := unix.ByteSliceToString(logEntry.Fmt[:])
		for i := 0; i < logarglen; i++ {
			arg := logEntry.Arg[i]

			// Find the next %u or %d in the log line.
			uIndex := strings.Index(logLine, `%u`)
			dIndex := strings.Index(logLine, `%d`)
			if uIndex == -1 && dIndex == -1 {
				break
			}
			if uIndex < dIndex || dIndex == -1 {
				logLine = strings.Replace(logLine, `%u`, fmt.Sprint(arg), 1)
			}
			if dIndex < uIndex || uIndex == -1 {
				logLine = strings.Replace(logLine, `%d`, fmt.Sprint(int32(arg)), 1)
			}
		}

		logFn(logEntry.UID, logEntry.GID, logEntry.PID, logLine)
	}
}

// Close gracefully closes and frees all resources associated with the eBPF
// tracepoints, maps and other resources. Any blocked `Read()` operations will
// return an error that wraps `io.EOF`.
func (t *tracer) Close() error {
	t.closeLock.Lock()
	defer t.closeLock.Unlock()
	select {
	case <-t.closed:
		return errTracerClosed
	default:
	}
	close(t.closed)
	runtime.SetFinalizer(t, nil)

	// Close everything started in h.Start() in reverse order.
	var merr error
	if t.rbLogs != nil {
		err := t.rbLogs.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close logs ringbuf reader: %w", err))
		}
	}
	if t.rbEvents != nil {
		err := t.rbEvents.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close events ringbuf reader: %w", err))
		}
	}
	if t.tp != nil {
		err := t.tp.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close tracepoint: %w", err))
		}
	}
	if t.objs != nil {
		err := t.objs.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf("close eBPF objects: %w", err))
		}
	}

	return merr
}
